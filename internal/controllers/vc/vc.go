// Package VC provides the controller for handling VIN VC-related requests.
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
	logger := v.logger.With().Uint32("vehicleTokenId", tokenID).Logger()
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
func (v *VCController) validateAndReconcileVINs(ctx context.Context, vehicleInfo *models.VehicleInfo, countryCode string) (string, error) {
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
func handleError(err error, logger *zerolog.Logger, message string) error {
	logger.Error().Err(err).Msg(message)
	return fiber.NewError(fiber.StatusInternalServerError, message)
}
