// Package vc provides the controller for handling VIN VC-related requests.
package vc

import (
	"context"
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

	return &Controller{
		logger:             logger,
		vcService:          vcService,
		identityService:    identityService,
		fingerprintService: fingerprintService,
		vinService:         vinService,
		telemetryBaseURL:   parsedURL,
	}, nil
}

func (v *Controller) getVINVC(ctx context.Context, tokenID uint32) (*getVINVCResponse, error) {
	logger := v.logger.With().Uint32("vehicleTokenId", tokenID).Logger()

	_, err := v.vcService.GetLatestVC(ctx, tokenID)
	if err == nil {
		logger.Debug().Msg("VC already exists")
		return v.generateSuccessResponse(tokenID), nil
	}

	vehicleInfo, err := v.identityService.GetVehicleInfo(ctx, tokenID)
	if err != nil {
		return nil, handleError(err, &logger, "Failed to get vehicle info")
	}
	vin, err := v.validateAndReconcileVINs(ctx, vehicleInfo, "")
	if err != nil {
		return nil, err
	}

	err = v.vcService.GenerateAndStoreVINVC(ctx, tokenID, vin, "")
	if err != nil {
		return nil, handleError(err, &logger, "Failed to generate and store VC")
	}

	return v.generateSuccessResponse(tokenID), nil
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

// generateSuccessResponse generates a success response for the given token ID.
func (v *Controller) generateSuccessResponse(tokenID uint32) *getVINVCResponse {
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
