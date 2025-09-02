package odometerstatementvc

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
)

// Service handles OdometerStatementVC-related operations.
type Service struct {
	vcRepo                 VCRepo
	identityAPI            IdentityAPI
	telemetryAPI           TelemetryAPI
	vehicleContractAddress common.Address
	chainID                uint64
	privateKey             *ecdsa.PrivateKey
	dataVersion            string
}

// NewService creates a new Service for OdometerStatementVC operations.
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

// CreateOdometerStatementVC creates an OdometerStatementVC.
// If timestamp is nil, it uses the latest odometer reading.
func (s *Service) CreateOdometerStatementVC(ctx context.Context, tokenID uint32, timestamp *time.Time, jwtToken string) error {
	vehicleDID := cloudevent.ERC721DID{
		ChainID:         s.chainID,
		TokenID:         big.NewInt(int64(tokenID)),
		ContractAddress: s.vehicleContractAddress,
	}

	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get vehicle info"}
	}

	odometerReading, producer, err := s.getOdometerReading(ctx, vehicleInfo, timestamp, jwtToken)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get odometer reading"}
	}

	subject := types.OdometerStatementVCSubject{
		VehicleDID:             vehicleDID.String(),
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress.Hex(),
		RecordedBy:             producer,
		OdometerReading:        *odometerReading,
		RequestedTimestamp:     timestamp,
	}

	vc, err := s.createAttestation(subject)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create OdometerStatementVC"}
	}

	if err = s.vcRepo.UploadAttestation(ctx, vc); err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store OdometerStatementVC"}
	}

	return nil
}

// getOdometerReading retrieves the odometer reading for the specified timestamp or latest using telemetry API.
func (s *Service) getOdometerReading(ctx context.Context, vehicleInfo *models.VehicleInfo, timestamp *time.Time, jwtToken string) (*types.OdometerReading, string, error) {
	var records []telemetryapi.TelemetryRecord
	var err error

	if timestamp != nil {
		// Search around the requested time
		startTime := timestamp.Add(-time.Hour)
		endTime := timestamp.Add(time.Hour)

		options := telemetryapi.TelemetryQueryOptions{
			TokenID:   int(vehicleInfo.DID.TokenID.Uint64()),
			StartDate: startTime.Format(time.RFC3339),
			EndDate:   endTime.Format(time.RFC3339),
			Signals:   []string{"powertrainTransmissionTravelledDistance"},
		}

		records, err = s.telemetryAPI.GetHistoricalDataWithAuth(ctx, options, jwtToken)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get odometer telemetry data: %w", err)
		}

		// Find closest odometer reading
		return s.findClosestOdometerFromTelemetry(records, *timestamp)
	}

	// Get latest odometer reading
	records, err = s.telemetryAPI.GetLatestSignalsWithAuth(ctx, int(vehicleInfo.DID.TokenID.Uint64()), jwtToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get latest telemetry data: %w", err)
	}

	return s.extractLatestOdometerFromTelemetry(records)
}

// findClosestOdometerFromTelemetry finds the odometer reading closest to the requested time.
func (s *Service) findClosestOdometerFromTelemetry(records []telemetryapi.TelemetryRecord, requestedTime time.Time) (*types.OdometerReading, string, error) {
	var closestReading *types.OdometerReading
	var closestTimeDiff time.Duration
	var producer string

	for _, record := range records {
		reading, err := s.extractOdometerFromTelemetry(record)
		if err != nil || reading == nil {
			continue
		}

		recordTime, err := time.Parse(time.RFC3339, record.Timestamp)
		if err != nil {
			continue
		}

		timeDiff := absTimeDiff(recordTime, requestedTime)
		if closestReading == nil || timeDiff < closestTimeDiff {
			closestReading = reading
			closestTimeDiff = timeDiff
			producer = record.Source
		}
	}

	if closestReading == nil {
		return nil, "", fmt.Errorf("no odometer data found")
	}

	return closestReading, producer, nil
}

// extractLatestOdometerFromTelemetry extracts the latest odometer reading from telemetry records.
func (s *Service) extractLatestOdometerFromTelemetry(records []telemetryapi.TelemetryRecord) (*types.OdometerReading, string, error) {
	var latestReading *types.OdometerReading
	var producer string

	for _, record := range records {
		reading, err := s.extractOdometerFromTelemetry(record)
		if err != nil || reading == nil {
			continue
		}

		if latestReading == nil {
			latestReading = reading
			producer = record.Source
		}
	}

	if latestReading == nil {
		return nil, "", fmt.Errorf("no odometer data found")
	}

	return latestReading, producer, nil
}

// extractOdometerFromTelemetry extracts odometer data from a telemetry record.
func (s *Service) extractOdometerFromTelemetry(record telemetryapi.TelemetryRecord) (*types.OdometerReading, error) {
	for _, signal := range record.Signals {
		// Check for the specific odometer signal from schema
		if signal.Name == "powertrainTransmissionTravelledDistance" {
			if odometerValue, ok := signal.Value.(float64); ok {
				// Skip if value is 0 or negative
				if odometerValue <= 0 {
					continue
				}

				// Parse signal timestamp or use record timestamp
				timestamp := record.Timestamp
				if signal.Timestamp != "" {
					timestamp = signal.Timestamp
				}

				recordTime, err := time.Parse(time.RFC3339, timestamp)
				if err != nil {
					recordTime = time.Now() // Fallback to now
				}

				// Default to km for travelled distance
				unit := "km"

				return &types.OdometerReading{
					Value:     odometerValue,
					Unit:      unit,
					Timestamp: recordTime,
				}, nil
			}
		}
	}

	return nil, nil // No odometer data in this record
}

// createAttestation creates the attestation cloud event.
func (s *Service) createAttestation(subject types.OdometerStatementVCSubject) (*cloudevent.RawEvent, error) {
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
