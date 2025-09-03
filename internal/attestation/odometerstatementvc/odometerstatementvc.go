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
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/ethereum/go-ethereum/common"
	"github.com/segmentio/ksuid"
)

const odometerUnit = "km"

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

	odometerReading, err := s.getOdometerReading(ctx, vehicleDID, timestamp, jwtToken)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get odometer reading"}
	}

	subject := types.OdometerStatementVCSubject{
		VehicleDID:         vehicleDID,
		OdometerReading:    *odometerReading,
		RequestedTimestamp: timestamp,
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
func (s *Service) getOdometerReading(ctx context.Context, vehicleInfo cloudevent.ERC721DID, requestTime *time.Time, jwtToken string) (*types.OdometerReading, error) {
	var records []telemetryapi.Signal
	var err error

	if requestTime != nil {
		// Search around the requested time
		startTime := requestTime.Add(-time.Hour)
		endTime := requestTime.Add(time.Hour)

		options := telemetryapi.TelemetryQueryOptions{
			TokenID:   vehicleInfo.TokenID,
			StartDate: startTime,
			EndDate:   endTime,
			Signals:   []string{vss.FieldPowertrainTransmissionTravelledDistance},
		}

		records, err = s.telemetryAPI.GetHistoricalDataWithAuth(ctx, options, jwtToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get odometer telemetry data: %w", err)
		}

		// Find closest odometer reading
		return s.findClosestOdometerFromTelemetry(records, *requestTime)
	}

	// Get latest odometer reading
	records, err = s.telemetryAPI.GetLatestSignalsWithAuth(ctx, vehicleInfo.TokenID, jwtToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest telemetry data: %w", err)
	}

	return s.findClosestOdometerFromTelemetry(records, time.Now())
}

// findClosestOdometerFromTelemetry finds the odometer reading closest to the requested time.
func (s *Service) findClosestOdometerFromTelemetry(signals []telemetryapi.Signal, requestedTime time.Time) (*types.OdometerReading, error) {
	var closestSignal *telemetryapi.Signal
	var closestTimeDiff time.Duration
	for _, signal := range signals {
		if !s.isOdometerSignal(signal) {
			continue
		}

		timeDiff := absTimeDiff(signal.Timestamp, requestedTime)
		if closestSignal == nil || timeDiff < closestTimeDiff {
			closestSignal = &signal
			closestTimeDiff = timeDiff
		}
	}

	if closestSignal == nil {
		return nil, fmt.Errorf("no odometer data found")
	}

	return &types.OdometerReading{
		Value:     closestSignal.Value.(float64),
		Unit:      odometerUnit,
		Timestamp: closestSignal.Timestamp,
	}, nil
}

// extractOdometerFromTelemetry extracts odometer data from a telemetry record.
func (s *Service) isOdometerSignal(signal telemetryapi.Signal) bool {
	// Check for the specific odometer signal from schema
	if signal.Name != "powertrainTransmissionTravelledDistance" {
		return false
	}

	odometerValue, ok := signal.Value.(float64)
	if !ok {
		return false
	}

	// Skip if value is 0 or negative
	if odometerValue <= 0 {
		return false
	}

	return true
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
			Subject:         subject.VehicleDID.String(),
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
