package vehiclepositionvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/ctrlerrors"
	"github.com/DIMO-Network/attestation-api/internal/erc191"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/common"
	"github.com/segmentio/ksuid"
	"github.com/uber/h3-go/v4"
)

const (
	// h3Resolution resolution for h3 hex 8 ~= 0.737327598 km2
	h3Resolution = 8
)

// Service handles VehiclePositionVC-related operations.
type Service struct {
	vcRepo                 VCRepo
	identityAPI            IdentityAPI
	telemetryAPI           TelemetryAPI
	vehicleContractAddress common.Address
	chainID                uint64
	privateKey             *ecdsa.PrivateKey
	dataVersion            string
}

// NewService creates a new Service for VehiclePositionVC operations.
func NewService(
	vcRepo VCRepo,
	identityAPI IdentityAPI,
	telemetryAPI TelemetryAPI,
	settings *config.Settings,
	privateKey *ecdsa.PrivateKey,
) *Service {
	return &Service{
		vcRepo:                 vcRepo,
		identityAPI:            identityAPI,
		telemetryAPI:           telemetryAPI,
		vehicleContractAddress: common.HexToAddress(settings.VehicleNFTAddress),
		chainID:                uint64(settings.DIMORegistryChainID),
		privateKey:             privateKey,
		dataVersion:            "1.0.0", // You may want to add this to settings
	}
}

// CreateVehiclePositionVC creates a VehiclePositionVC for a specific timestamp.
func (s *Service) CreateVehiclePositionVC(ctx context.Context, tokenID uint32, timestamp time.Time, jwtToken string) error {
	vehicleDID := cloudevent.ERC721DID{
		ChainID:         s.chainID,
		TokenID:         big.NewInt(int64(tokenID)),
		ContractAddress: s.vehicleContractAddress,
	}

	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get vehicle info"}
	}

	location, producer, err := s.findClosestLocation(ctx, vehicleInfo, timestamp, jwtToken)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to find location data"}
	}

	subject := types.VehiclePositionVCSubject{
		VehicleDID:             vehicleDID.String(),
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress.Hex(),
		RecordedBy:             producer,
		Location:               *location,
		RequestedTimestamp:     timestamp,
	}

	vc, err := s.createAttestation(subject)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create VehiclePositionVC"}
	}

	if err = s.vcRepo.UploadAttestation(ctx, vc); err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store VehiclePositionVC"}
	}

	return nil
}

// findClosestLocation finds the location closest to the requested timestamp using telemetry API.
func (s *Service) findClosestLocation(ctx context.Context, vehicleInfo *models.VehicleInfo, requestedTime time.Time, jwtToken string) (*types.Location, string, error) {
	// Define time window around requested timestamp (1 hour before and after)
	startTime := requestedTime.Add(-time.Hour)
	endTime := requestedTime.Add(time.Hour)

	options := telemetryapi.TelemetryQueryOptions{
		TokenID:   int(vehicleInfo.DID.TokenID.Uint64()),
		StartDate: startTime.Format(time.RFC3339),
		EndDate:   endTime.Format(time.RFC3339),
		Signals:   []string{"currentLocationLatitude", "currentLocationLongitude", "currentLocationApproximateLatitude", "currentLocationApproximateLongitude"},
	}

	// Get historical telemetry data
	records, err := s.telemetryAPI.GetHistoricalDataWithAuth(ctx, options, jwtToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get telemetry data: %w", err)
	}

	if len(records) == 0 {
		// Try with latest signals if no historical data found
		records, err = s.telemetryAPI.GetLatestSignalsWithAuth(ctx, int(vehicleInfo.DID.TokenID.Uint64()), jwtToken)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get latest telemetry data: %w", err)
		}
	}

	// Find the location closest to requested timestamp
	var closestLocation *types.Location
	var closestTimeDiff time.Duration
	var producer string

	for _, record := range records {
		location, err := s.extractLocationFromTelemetry(record)
		if err != nil || location == nil {
			continue
		}

		recordTime, err := time.Parse(time.RFC3339, record.Timestamp)
		if err != nil {
			continue
		}

		timeDiff := absTimeDiff(recordTime, requestedTime)
		if closestLocation == nil || timeDiff < closestTimeDiff {
			closestLocation = location
			closestTimeDiff = timeDiff
			producer = record.Source
		}
	}

	if closestLocation == nil {
		return nil, "", fmt.Errorf("no location data found in telemetry")
	}

	return closestLocation, producer, nil
}

// extractLocationFromTelemetry extracts location data from a telemetry record.
func (s *Service) extractLocationFromTelemetry(record telemetryapi.TelemetryRecord) (*types.Location, error) {
	var latitude, longitude *float64

	// Extract latitude and longitude from signals
	for _, signal := range record.Signals {
		switch signal.Name {
		case "currentLocationLatitude", "currentLocationApproximateLatitude":
			if lat, ok := signal.Value.(float64); ok {
				latitude = &lat
			}
		case "currentLocationLongitude", "currentLocationApproximateLongitude":
			if lng, ok := signal.Value.(float64); ok {
				longitude = &lng
			}
		}
	}

	// Check if we have both coordinates
	if latitude == nil || longitude == nil {
		return nil, fmt.Errorf("incomplete location data")
	}

	// Convert to H3 cell
	h3LatLng := h3.NewLatLng(*latitude, *longitude)
	cell, err := h3.LatLngToCell(h3LatLng, h3Resolution)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to H3 cell: %w", err)
	}

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, record.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	location := &types.Location{
		LocationType: types.LocationTypeH3Cell,
		LocationValue: types.H3Cell{
			CellID: cell.String(),
		},
		Timestamp: timestamp,
	}

	return location, nil
}

// createAttestation creates the attestation cloud event.
func (s *Service) createAttestation(subject types.VehiclePositionVCSubject) (*cloudevent.RawEvent, error) {
	issuanceDate := time.Now().UTC()
	expirationDate := issuanceDate.Add(30 * 24 * time.Hour) // Valid for 30 days

	credential := types.Credential{
		ValidFrom: issuanceDate,
		ValidTo:   expirationDate,
	}

	rawSubject, err := json.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential subject: %w", err)
	}
	credential.CredentialSubject = rawSubject

	marshaledCreds, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	signature, err := erc191.SignMessage(marshaledCreds, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	cloudEvent := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion:     "1.0",
			ID:              ksuid.New().String(),
			Time:            issuanceDate,
			Source:          sources.DINCSource.String(),
			Subject:         subject.VehicleDID,
			Producer:        subject.RecordedBy,
			Type:            cloudevent.TypeAttestation,
			DataContentType: "application/json",
			DataVersion:     s.dataVersion,
			Signature:       signature,
		},
		Data: marshaledCreds,
	}

	return &cloudEvent, nil
}

// absTimeDiff returns the absolute difference between two times.
func absTimeDiff(a, b time.Time) time.Duration {
	diff := a.Sub(b)
	if diff < 0 {
		return -diff
	}
	return diff
}
