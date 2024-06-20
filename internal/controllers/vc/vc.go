// Package VC provides the controller for handling VIN VC-related requests.
package vc

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/gofiber/fiber/v2"
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

func (v *VCController) getVINVC(ctx context.Context, tokenID uint32) (*getVINVCResponse, error) {
	pairedDevices, err := v.identityService.GetPairedDevices(ctx, tokenID)
	if err != nil {
		return nil, v.handleError(err, "Failed to get paired devices")
	}
	if len(pairedDevices) == 0 {
		return nil, fiber.NewError(fiber.StatusNotFound, "No paired devices found")
	}

	vin, err := v.validateAndReconcileVINs(ctx, pairedDevices)
	if err != nil {
		return nil, err
	}

	err = v.vcService.GenerateAndStoreVINVC(ctx, tokenID, vin)
	if err != nil {
		return nil, v.handleError(err, "Failed to generate and store VC")
	}

	vcURL, gqlQuery := v.generateVCURLAndQuery(tokenID)

	return &getVINVCResponse{
		VCURL:   vcURL,
		VCQuery: gqlQuery,
		Message: "VC generated successfully. Retrieve using the provided GQL URL and query parameter.",
	}, nil
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
func (v *VCController) validateAndReconcileVINs(ctx context.Context, pairedDevices []models.PairedDevice) (string, error) {
	if len(pairedDevices) == 0 {
		return "", fiber.NewError(fiber.StatusInternalServerError, "No paired devices")
	}

	var latestVIN string
	var latestTimestamp time.Time

	for _, device := range pairedDevices {
		fingerprint, err := v.fingerprintService.GetLatestFingerprintMessages(ctx, device.Address)
		if err != nil {
			return "", v.handleError(err, "Failed to get fingerprint messages")
		}

		currentVIN := fingerprint.VIN
		if latestVIN == "" || fingerprint.Timestamp.After(latestTimestamp) {
			latestVIN = currentVIN
			latestTimestamp = fingerprint.Timestamp
		}
	}

	if err := v.vinService.ValidateVIN(ctx, latestVIN); err != nil {
		return "", v.handleError(err, "Failed to validate VIN")
	}

	return latestVIN, nil
}

// generateVCURLAndQuery generates the URL and GraphQL query for retrieving the VC
func (v *VCController) generateVCURLAndQuery(tokenID uint32) (string, string) {
	vcPath := path.Join(v.telemetryBaseURL.Path, "vc")
	fullURL := &url.URL{
		Scheme: v.telemetryBaseURL.Scheme,
		Host:   v.telemetryBaseURL.Host,
		Path:   vcPath,
	}

	gqlQuery := fmt.Sprintf(`
	{
		vc(tokenID: "%d") {
			id
			vin
			issuanceDate
			expirationDate
			issuer
			proof
			metadata
		}
	}`, tokenID)
	return fullURL.String(), gqlQuery
}

// handleError logs an error and returns a Fiber error with the given message
func (v *VCController) handleError(err error, message string) error {
	v.logger.Error().Err(err).Msg(message)
	return fiber.NewError(fiber.StatusInternalServerError, message)
}
