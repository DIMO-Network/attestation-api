// Package VC provides the controller for handling VIN VC-related requests.
package vc

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// VCController handles VIN VC-related requests.
type VCController struct {
	logger             *zerolog.Logger
	vcService          VCService
	identityService    IdentityService
	fingerprintService FingerprintService
	vinService         VINService
	telemetryBaseURL   *url.URL
}

// NewVCController creates a new VCController instance.
func NewVCController(
	logger *zerolog.Logger,
	vcService VCService,
	identityService IdentityService,
	fingerprintService FingerprintService,
	vinService VINService,
	telemetryURL string,
) (*VCController, error) {
	// Parse and sanitize the telemetry URL
	parsedURL, err := sanitizeTelemetryURL(telemetryURL)
	if err != nil {
		return nil, err
	}

	return &VCController{
		logger:             logger,
		vcService:          vcService,
		identityService:    identityService,
		fingerprintService: fingerprintService,
		vinService:         vinService,
		telemetryBaseURL:   parsedURL,
	}, nil
}

// GetVINVC handles requests to issue a VIN VC
func (v *VCController) GetVINVC(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Query("token_id")
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "token_id query parameter is required")
	}

	tokenID, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
	}

	pairedDevices, err := v.identityService.GetPairedDevices(ctx, uint32(tokenID))
	if err != nil {
		return v.handleError(err, "Failed to get paired devices")
	}
	if len(pairedDevices) == 0 {
		return fiber.NewError(fiber.StatusNotFound, "No paired devices found")
	}

	vin, aftermarketTokenID, syntheticTokenID, err := v.validateAndReconcileVINs(ctx, pairedDevices)
	if err != nil {
		return err
	}

	vcUUID := uuid.New().String()

	if err := v.vcService.GenerateAndStoreVC(ctx, vcUUID, uint32(tokenID), aftermarketTokenID, syntheticTokenID, vin); err != nil {
		return v.handleError(err, "Failed to generate and store VC")
	}

	vcURL, gqlQuery := v.generateVCURLAndQuery(vcUUID)

	return fiberCtx.Status(fiber.StatusOK).JSON(fiber.Map{
		"vc_url":   vcURL,
		"vc_query": gqlQuery,
		"message":  "VC generated successfully. Retrieve using the provided URL and query parameter.",
	})
}

// sanitizeTelemetryURL parses and sanitizes the given telemetry URL.
func sanitizeTelemetryURL(telemetryURL string) (*url.URL, error) {
	parsedURL, err := url.ParseRequestURI(telemetryURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid telemetry URL: %s", telemetryURL)
	}
	return parsedURL, nil
}

// validateAndReconcileVINs validates and reconciles VINs from the paired devices.
func (v *VCController) validateAndReconcileVINs(ctx context.Context, pairedDevices []models.PairedDevice) (string, *uint32, *uint32, error) {
	if len(pairedDevices) == 0 {
		return "", nil, nil, fiber.NewError(fiber.StatusInternalServerError, "No paired devices")
	}

	var latestVIN string
	var latestTimestamp time.Time
	var aftermarketTokenID *uint32
	var syntheticTokenID *uint32

	for _, device := range pairedDevices {
		fingerprints, err := v.fingerprintService.GetLatestFingerprintMessages(ctx, device.TokenID)
		if err != nil {
			return "", nil, nil, v.handleError(err, "Failed to get fingerprint messages")
		}

		if len(fingerprints) > 0 {
			currentVIN := fingerprints[0].VIN
			if latestVIN == "" || fingerprints[0].Timestamp.After(latestTimestamp) {
				latestVIN = currentVIN
				latestTimestamp = fingerprints[0].Timestamp
				aftermarketTokenID = nil
				syntheticTokenID = nil
			}

			// Check if the TokenID belongs to aftermarket or synthetic
			if device.Type == models.DeviceTypeAftermarket && latestVIN == currentVIN {
				aftermarketTokenID = &device.TokenID
			} else if device.Type == models.DeviceTypeSynthetic && latestVIN == currentVIN {
				syntheticTokenID = &device.TokenID
			}
		}
	}

	if err := v.vinService.ValidateVIN(ctx, latestVIN); err != nil {
		return "", nil, nil, v.handleError(err, "Failed to validate VIN")
	}

	return latestVIN, aftermarketTokenID, syntheticTokenID, nil
}

// generateVCURLAndQuery generates the URL and GraphQL query for retrieving the VC
func (v *VCController) generateVCURLAndQuery(vcUUID string) (string, string) {
	vcPath := path.Join(v.telemetryBaseURL.Path, "vc")
	fullURL := &url.URL{
		Scheme: v.telemetryBaseURL.Scheme,
		Host:   v.telemetryBaseURL.Host,
		Path:   vcPath,
	}

	gqlQuery := fmt.Sprintf(`
	{
		vc(uuid: "%s") {
			id
			vin
			issuanceDate
			expirationDate
			issuer
			proof
			metadata
		}
	}`, vcUUID)
	return fullURL.String(), gqlQuery
}

// handleError logs an error and returns a Fiber error with the given message
func (v *VCController) handleError(err error, message string) error {
	v.logger.Error().Err(err).Msg(message)
	return fiber.NewError(fiber.StatusInternalServerError, message)
}
