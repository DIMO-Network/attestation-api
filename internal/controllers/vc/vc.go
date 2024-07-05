// Package vc provides the controller for handling VIN VC-related requests.
package vc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// Controller handles VIN VC-related requests.
type Controller struct {
	logger             *zerolog.Logger
	vcService          VCService
	identityService    IdentityService
	fingerprintService FingerprintService
	vinService         VINService
	telemetryBaseURL   *url.URL
	publicKeyDoc       json.RawMessage
}

// NewVCController creates a new VCController instance.
func NewVCController(
	logger *zerolog.Logger,
	vcService VCService,
	identityService IdentityService,
	fingerprintService FingerprintService,
	vinService VINService,
	telemetryURL string,
) (*Controller, error) {
	// Parse and sanitize the telemetry URL
	parsedURL, err := sanitizeTelemetryURL(telemetryURL)
	if err != nil {
		return nil, err
	}

	publicKeyDoc, err := vcService.GenerateKeyControlDocument()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key control document: %w", err)
	}

	return &Controller{
		logger:             logger,
		vcService:          vcService,
		identityService:    identityService,
		fingerprintService: fingerprintService,
		vinService:         vinService,
		telemetryBaseURL:   parsedURL,
		publicKeyDoc:       publicKeyDoc,
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

// getOrCreateVC retrieves or generates a VC for the given token ID.
func (v *Controller) getOrCreateVC(ctx context.Context, tokenID uint32, force bool) (*getVINVCResponse, error) {
	logger := v.logger.With().Uint32("vehicleTokenId", tokenID).Logger()

	if !force && v.hasValidVC(ctx, tokenID) {
		logger.Debug().Msg("Valid VC already exists skipping generation")
		return v.successResponse(tokenID), nil
	}
	return v.generateVINVC(ctx, tokenID, &logger)
}

// hasValidVC checks if a valid VC exists for the given token ID.
func (v *Controller) hasValidVC(ctx context.Context, tokenID uint32) bool {
	prevVC, err := v.vcService.GetLatestVC(ctx, tokenID)
	if err == nil {
		expireDate, err := time.Parse(time.RFC3339, prevVC.ExpirationDate)
		if err == nil && time.Now().Before(expireDate) {
			return true
		}
	}
	return false
}

func (v *Controller) generateVINVC(ctx context.Context, tokenID uint32, logger *zerolog.Logger) (*getVINVCResponse, error) {
	vehicleInfo, err := v.identityService.GetVehicleInfo(ctx, tokenID)
	if err != nil {
		return nil, handleError(err, logger, "Failed to get vehicle info")
	}
	vin, err := v.validateAndReconcileVINs(ctx, vehicleInfo, "")
	if err != nil {
		return nil, err
	}

	err = v.vcService.GenerateAndStoreVINVC(ctx, tokenID, vin, "")
	if err != nil {
		return nil, handleError(err, logger, "Failed to generate and store VC")
	}

	return v.successResponse(tokenID), nil
}

// validateAndReconcileVINs validates and reconciles VINs from the paired devices.
func (v *Controller) validateAndReconcileVINs(ctx context.Context, vehicleInfo *models.VehicleInfo, countryCode string) (string, error) {
	if len(vehicleInfo.PairedDevices) == 0 {
		return "", fiber.NewError(fiber.StatusBadRequest, "No paired devices")
	}
	logger := v.logger.With().Uint32("vehicleTokenId", vehicleInfo.TokenID).Logger()
	var latestVIN string
	var latestTimestamp time.Time

	var fingerprintErr error
	for _, device := range vehicleInfo.PairedDevices {
		fingerprint, err := v.fingerprintService.GetLatestFingerprintMessages(ctx, device.Address)
		if err != nil {
			// log the error and continue to the next device if possible
			localLogger := logger.With().Str("device", device.Address.Hex()).Logger()
			err := handleError(err, &localLogger, "Failed to get latest fingerprint message")
			fingerprintErr = errors.Join(fingerprintErr, err)
			continue
		}

		currentVIN := fingerprint.VIN
		if latestVIN == "" || fingerprint.Timestamp.After(latestTimestamp) {
			latestVIN = currentVIN
			latestTimestamp = fingerprint.Timestamp
		}
	}

	// return error to the user if no VINs were found
	if latestVIN == "" && fingerprintErr != nil {
		return "", fingerprintErr
	}
	decodedNameSlug, err := v.vinService.DecodeVIN(ctx, latestVIN, countryCode)
	if err != nil {
		return "", handleError(err, &logger, "Failed to decode VIN")
	}
	if decodedNameSlug != vehicleInfo.NameSlug {
		message := "Invalid VIN from fingerprint"
		logger.Error().Str("decodedNameSlug", decodedNameSlug).Str("vehicleNameSlug", vehicleInfo.NameSlug).Msg(message)
		return "", fiber.NewError(fiber.StatusBadRequest, message)
	}

	return latestVIN, nil
}

// successResponse generates a success response for the given token ID.
func (v *Controller) successResponse(tokenID uint32) *getVINVCResponse {
	vcPath := path.Join(v.telemetryBaseURL.Path, "vc")
	fullURL := &url.URL{
		Scheme: v.telemetryBaseURL.Scheme,
		Host:   v.telemetryBaseURL.Host,
		Path:   vcPath,
	}

	gqlQuery := fmt.Sprintf(`
	query {
		vinVCLatest(tokenId: %d) {
			rawVC
		}
	}`, tokenID)
	return &getVINVCResponse{
		VCURL:   fullURL.String(),
		VCQuery: gqlQuery,
		Message: "VC generated successfully. Retrieve using the provided GQL URL and query parameter.",
	}
}

// handleError logs an error and returns a Fiber error with the given message.
func handleError(err error, logger *zerolog.Logger, message string) error {
	logger.Error().Err(err).Msg(message)
	return fiber.NewError(fiber.StatusInternalServerError, message)
}
