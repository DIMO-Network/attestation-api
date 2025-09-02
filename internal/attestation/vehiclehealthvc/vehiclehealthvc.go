package vehiclehealthvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
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

const (
	// Tire pressure thresholds (in PSI)
	minNormalTirePressure = 30.0
	maxNormalTirePressure = 40.0
)

// Service handles VehicleHealthVC-related operations.
type Service struct {
	vcRepo                 VCRepo
	identityAPI            IdentityAPI
	telemetryAPI           TelemetryAPI
	vehicleContractAddress common.Address
	chainID                uint64
	privateKey             *ecdsa.PrivateKey
	dataVersion            string
}

// NewService creates a new Service for VehicleHealthVC operations.
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

// CreateVehicleHealthVC creates a VehicleHealthVC for a specific time range.
// Note: The time range validation (max 30 days) is performed at the HTTP handler level.
func (s *Service) CreateVehicleHealthVC(ctx context.Context, tokenID uint32, startTime, endTime time.Time, jwtToken string) error {
	vehicleDID := cloudevent.ERC721DID{
		ChainID:         s.chainID,
		TokenID:         big.NewInt(int64(tokenID)),
		ContractAddress: s.vehicleContractAddress,
	}

	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get vehicle info"}
	}

	healthStatus, producer, err := s.analyzeVehicleHealth(ctx, vehicleInfo, startTime, endTime, jwtToken)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to analyze vehicle health"}
	}

	subject := types.VehicleHealthVCSubject{
		VehicleDID:             vehicleDID.String(),
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress.Hex(),
		RecordedBy:             producer,
		HealthStatus:           *healthStatus,
		SearchedTimeRange: types.TimeRange{
			Start: startTime,
			End:   endTime,
		},
	}

	vc, err := s.createAttestation(subject)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create VehicleHealthVC"}
	}

	if err = s.vcRepo.UploadAttestation(ctx, vc); err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store VehicleHealthVC"}
	}

	return nil
}

// analyzeVehicleHealth analyzes vehicle health data within the time range using telemetry API.
func (s *Service) analyzeVehicleHealth(ctx context.Context, vehicleInfo *models.VehicleInfo, startTime, endTime time.Time, jwtToken string) (*types.VehicleHealthStatus, string, error) {
	// Query telemetry data for health-related signals
	options := telemetryapi.TelemetryQueryOptions{
		TokenID:   int(vehicleInfo.DID.TokenID.Uint64()),
		StartDate: startTime.Format(time.RFC3339),
		EndDate:   endTime.Format(time.RFC3339),
		Signals: []string{
			"obdDTCList",
			"obdStatusDTCCount",
			"chassisAxleRow1WheelLeftTirePressure",
			"chassisAxleRow1WheelRightTirePressure",
			"chassisAxleRow2WheelLeftTirePressure",
			"chassisAxleRow2WheelRightTirePressure",
		},
	}

	// Get health data from telemetry API
	records, err := s.telemetryAPI.GetHistoricalDataWithAuth(ctx, options, jwtToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get health telemetry data: %w", err)
	}

	if len(records) == 0 {
		return nil, "", fmt.Errorf("no health data found in the specified time range")
	}

	// Process records to extract health information
	healthStatus := s.processHealthTelemetryRecords(records)

	// Calculate health score and overall health status
	s.calculateHealthScore(healthStatus)

	// Use the most recent record source as producer
	producer := "telemetry-api"
	if len(records) > 0 {
		producer = records[0].Source
	}

	return healthStatus, producer, nil
}

// processHealthTelemetryRecords processes telemetry records to extract health status.
func (s *Service) processHealthTelemetryRecords(records []telemetryapi.TelemetryRecord) *types.VehicleHealthStatus {
	dtcMap := make(map[string]types.DiagnosticTroubleCode)
	var latestTirePressure *types.TirePressureStatus
	var lastUpdated time.Time

	for _, record := range records {
		// Parse record timestamp
		recordTime, err := time.Parse(time.RFC3339, record.Timestamp)
		if err != nil {
			continue
		}

		// Update last timestamp
		if recordTime.After(lastUpdated) {
			lastUpdated = recordTime
		}

		// Extract DTCs
		dtcs := s.extractDTCsFromTelemetry(record)
		for _, dtc := range dtcs {
			// Store unique DTCs by code
			if _, exists := dtcMap[dtc.Code]; !exists {
				dtcMap[dtc.Code] = dtc
			}
		}

		// Extract tire pressure
		tirePressure := s.extractTirePressureFromTelemetry(record)
		if tirePressure != nil {
			latestTirePressure = tirePressure
		}
	}

	// Convert DTCs map to slice
	dtcs := make([]types.DiagnosticTroubleCode, 0, len(dtcMap))
	for _, dtc := range dtcMap {
		dtcs = append(dtcs, dtc)
	}

	return &types.VehicleHealthStatus{
		DTCs:         dtcs,
		TirePressure: latestTirePressure,
		LastUpdated:  lastUpdated,
	}
}

// extractDTCsFromTelemetry extracts diagnostic trouble codes from a telemetry record.
func (s *Service) extractDTCsFromTelemetry(record telemetryapi.TelemetryRecord) []types.DiagnosticTroubleCode {
	var dtcs []types.DiagnosticTroubleCode

	for _, signal := range record.Signals {
		// Check for OBD DTC List
		if signal.Name == "obdDTCList" {
			if dtcValue, ok := signal.Value.(string); ok && dtcValue != "" {
				// Parse DTC codes (could be comma-separated)
				codes := strings.Split(dtcValue, ",")
				for _, code := range codes {
					code = strings.TrimSpace(code)
					if code != "" && code != "0" && code != "00000" {
						timestamp, _ := time.Parse(time.RFC3339, signal.Timestamp)
						dtc := types.DiagnosticTroubleCode{
							Code:      code,
							Severity:  s.categorizeDTCSeverity(code),
							Timestamp: timestamp,
						}
						dtcs = append(dtcs, dtc)
					}
				}
			}
		}
		// Check for DTC count to infer MIL status
		if signal.Name == "obdStatusDTCCount" {
			if dtcCount, ok := signal.Value.(float64); ok && dtcCount > 0 {
				timestamp, _ := time.Parse(time.RFC3339, signal.Timestamp)
				dtc := types.DiagnosticTroubleCode{
					Code:        "MIL_ON",
					Description: "Check Engine Light is ON (DTC count > 0)",
					Severity:    "warning",
					Timestamp:   timestamp,
				}
				dtcs = append(dtcs, dtc)
			}
		}
	}

	return dtcs
}

// extractTirePressureFromTelemetry extracts tire pressure data from a telemetry record.
func (s *Service) extractTirePressureFromTelemetry(record telemetryapi.TelemetryRecord) *types.TirePressureStatus {
	tirePressure := &types.TirePressureStatus{
		Unit:      "psi",      // Default to PSI
		Timestamp: time.Now(), // Default timestamp
	}

	// Parse record timestamp
	if recordTime, err := time.Parse(time.RFC3339, record.Timestamp); err == nil {
		tirePressure.Timestamp = recordTime
	}

	foundAny := false

	for _, signal := range record.Signals {
		// Check for specific tire pressure signals from schema
		switch signal.Name {
		case "chassisAxleRow1WheelLeftTirePressure":
			if pressureValue, ok := signal.Value.(float64); ok {
				tirePressure.FrontLeft = &pressureValue
				foundAny = true
			}
		case "chassisAxleRow1WheelRightTirePressure":
			if pressureValue, ok := signal.Value.(float64); ok {
				tirePressure.FrontRight = &pressureValue
				foundAny = true
			}
		case "chassisAxleRow2WheelLeftTirePressure":
			if pressureValue, ok := signal.Value.(float64); ok {
				tirePressure.RearLeft = &pressureValue
				foundAny = true
			}
		case "chassisAxleRow2WheelRightTirePressure":
			if pressureValue, ok := signal.Value.(float64); ok {
				tirePressure.RearRight = &pressureValue
				foundAny = true
			}
		}
	}

	if !foundAny {
		return nil
	}

	// Check if all pressures are normal
	tirePressure.IsNormal = s.isTirePressureNormal(tirePressure)

	return tirePressure
}

// categorizeDTCSeverity categorizes DTC severity based on the code.
func (s *Service) categorizeDTCSeverity(code string) string {
	// P0XXX codes are powertrain
	// P1XXX codes are manufacturer specific
	// C0XXX codes are chassis
	// B0XXX codes are body
	// U0XXX codes are network

	if strings.HasPrefix(code, "P0") {
		// Common critical codes
		if strings.HasPrefix(code, "P01") || strings.HasPrefix(code, "P02") {
			return "critical" // Fuel and air metering
		}
		if strings.HasPrefix(code, "P03") || strings.HasPrefix(code, "P04") {
			return "warning" // Ignition system or auxiliary emission
		}
	}

	if strings.HasPrefix(code, "U") {
		return "warning" // Network communication codes
	}

	return "info" // Default to info
}

// isTirePressureNormal checks if all tire pressures are within normal range.
func (s *Service) isTirePressureNormal(tp *types.TirePressureStatus) bool {
	pressures := []*float64{tp.FrontLeft, tp.FrontRight, tp.RearLeft, tp.RearRight}

	for _, pressure := range pressures {
		if pressure != nil {
			if *pressure < minNormalTirePressure || *pressure > maxNormalTirePressure {
				return false
			}
		}
	}

	return true
}

// calculateHealthScore calculates the overall health score.
func (s *Service) calculateHealthScore(status *types.VehicleHealthStatus) {
	score := 100

	// Deduct points for DTCs based on severity
	for _, dtc := range status.DTCs {
		switch dtc.Severity {
		case "critical":
			score -= 30
		case "warning":
			score -= 15
		case "info":
			score -= 5
		}
	}

	// Deduct points for abnormal tire pressure
	if status.TirePressure != nil && !status.TirePressure.IsNormal {
		score -= 20
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	status.HealthScore = score
	status.IsHealthy = score >= 70 // Consider healthy if score is 70 or above
}

// createAttestation creates the attestation cloud event.
func (s *Service) createAttestation(subject types.VehicleHealthVCSubject) (*cloudevent.RawEvent, error) {
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
