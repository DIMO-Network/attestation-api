package vehiclehealthvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/erc191"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/segmentio/ksuid"
)

const (
	// Tire pressure thresholds (in kPa)
	minNormalTirePressure   = 206.84 // 30 psi
	maxNormalTirePressure   = 275.79 // 40 psi
	defaultTirePressureUnit = "kPa"
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

	healthStatus, err := s.analyzeVehicleHealth(ctx, &vehicleDID, startTime, endTime, jwtToken)
	if err != nil {
		return richerrors.Error{Err: err, ExternalMsg: "Failed to analyze vehicle health"}
	}

	subject := types.VehicleHealthVCSubject{
		VehicleDID:   vehicleDID,
		HealthStatus: *healthStatus,
		SearchedTimeRange: types.TimeRange{
			Start: startTime,
			End:   endTime,
		},
	}

	vc, err := s.createAttestation(subject)
	if err != nil {
		return richerrors.Error{Err: err, ExternalMsg: "Failed to create VehicleHealthVC"}
	}

	if err = s.vcRepo.UploadAttestation(ctx, vc); err != nil {
		return richerrors.Error{Err: err, ExternalMsg: "Failed to store VehicleHealthVC"}
	}

	return nil
}

// analyzeVehicleHealth analyzes vehicle health data within the time range using telemetry API.
func (s *Service) analyzeVehicleHealth(ctx context.Context, vehicleDID *cloudevent.ERC721DID, startTime, endTime time.Time, jwtToken string) (*types.VehicleHealthStatus, error) {
	// Query telemetry data for health-related signals
	options := telemetryapi.TelemetryHistoricalOptions{
		TokenID:   vehicleDID.TokenID,
		StartDate: startTime,
		EndDate:   endTime,
		Interval:  "5m",
		Signals: []string{
			vss.FieldOBDDTCList,
			vss.FieldOBDStatusDTCCount,
			vss.FieldChassisAxleRow1WheelLeftTirePressure,
			vss.FieldChassisAxleRow1WheelRightTirePressure,
			vss.FieldChassisAxleRow2WheelLeftTirePressure,
			vss.FieldChassisAxleRow2WheelRightTirePressure,
		},
	}

	// Get health data from telemetry API
	signals, err := s.telemetryAPI.GetHistoricalDataWithAuth(ctx, options, jwtToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get health telemetry data: %w", err)
	}

	if len(signals) == 0 {
		return nil, fmt.Errorf("no health data found in the specified time range")
	}
	slices.SortFunc(signals, func(i, j telemetryapi.Signal) int {
		// sort in descending order
		return -i.Timestamp.Compare(j.Timestamp)
	})

	// Process records to extract health information
	healthStatus := processHealthTelemetrySignals(signals)

	// Calculate health score and overall health status
	s.calculateHealthScore(healthStatus)

	return healthStatus, nil
}

// processHealthTelemetrySignals processes telemetry signals to extract health status.
func processHealthTelemetrySignals(signals []telemetryapi.Signal) *types.VehicleHealthStatus {
	dtcMap := make(map[string]types.DiagnosticTroubleCode)
	var latestTirePressure *types.TirePressureStatus
	var lastUpdated time.Time

	for _, signal := range signals {
		// Update last timestamp
		if signal.Timestamp.After(lastUpdated) {
			lastUpdated = signal.Timestamp
		}

		// Extract DTCs
		dtcs := extractDTCsFromTelemetry(signal)
		for _, dtc := range dtcs {
			// Store unique DTCs by code
			if _, exists := dtcMap[dtc.Code]; !exists {
				dtcMap[dtc.Code] = dtc
			}
		}

		// Extract tire pressure
		latestTirePressure = updateTirePressureFromTelemetry(signal, latestTirePressure)
	}

	// Convert DTCs map to slice
	dtcs := make([]types.DiagnosticTroubleCode, 0, len(dtcMap))
	for _, dtc := range dtcMap {
		dtcs = append(dtcs, dtc)
	}

	// Check if all pressures are normal
	if latestTirePressure != nil {
		latestTirePressure.IsNormal = isTirePressureNormal(latestTirePressure)
	}

	return &types.VehicleHealthStatus{
		DTCs:         dtcs,
		TirePressure: latestTirePressure,
		LastUpdated:  lastUpdated,
	}
}

// extractDTCsFromTelemetry extracts diagnostic trouble codes from a telemetry record.
func extractDTCsFromTelemetry(signal telemetryapi.Signal) []types.DiagnosticTroubleCode {
	var dtcs []types.DiagnosticTroubleCode

	switch signal.Name {
	case vss.FieldOBDDTCList:
		dtcValue, ok := signal.Value.(string)
		if !ok || dtcValue == "" {
			return dtcs
		}
		var codes []string
		if err := json.Unmarshal([]byte(dtcValue), &codes); err != nil {
			return dtcs
		}
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "0" && code != "00000" {
				dtc := types.DiagnosticTroubleCode{
					Code:      code,
					Severity:  categorizeDTCSeverity(code),
					Timestamp: signal.Timestamp,
				}
				dtcs = append(dtcs, dtc)
			}
		}

	// Check for DTC count to infer MIL status
	case vss.FieldOBDStatusDTCCount:
		dtcCount, ok := signal.Value.(float64)
		if !ok || dtcCount <= 0 {
			return dtcs
		}
		dtc := types.DiagnosticTroubleCode{
			Code:        "MIL_ON",
			Description: "Check Engine Light is ON (DTC count > 0)",
			Severity:    "warning",
			Timestamp:   signal.Timestamp,
		}
		dtcs = append(dtcs, dtc)
	}

	return dtcs
}

// updateTirePressureFromTelemetry updates tire pressure data from a telemetry record.
func updateTirePressureFromTelemetry(signal telemetryapi.Signal, tirePressure *types.TirePressureStatus) *types.TirePressureStatus {
	if tirePressure == nil {
		tirePressure = &types.TirePressureStatus{
			Unit: defaultTirePressureUnit, // Default to kpa
		}
	}

	// Check for specific tire pressure signals from schema
	switch signal.Name {
	case vss.FieldChassisAxleRow1WheelLeftTirePressure:
		pressureValue, ok := signal.Value.(float64)
		if !ok || tirePressure.FrontLeft != nil {
			return tirePressure
		}
		tirePressure.FrontLeft = &pressureValue
		tirePressure.Timestamp = signal.Timestamp
	case vss.FieldChassisAxleRow1WheelRightTirePressure:
		pressureValue, ok := signal.Value.(float64)
		if !ok || tirePressure.FrontRight != nil {
			return tirePressure
		}
		tirePressure.FrontRight = &pressureValue
		tirePressure.Timestamp = signal.Timestamp
	case vss.FieldChassisAxleRow2WheelLeftTirePressure:
		pressureValue, ok := signal.Value.(float64)
		if !ok || tirePressure.RearLeft != nil {
			return tirePressure
		}
		tirePressure.RearLeft = &pressureValue
		tirePressure.Timestamp = signal.Timestamp
	case vss.FieldChassisAxleRow2WheelRightTirePressure:
		pressureValue, ok := signal.Value.(float64)
		if !ok || tirePressure.RearRight != nil {
			return tirePressure
		}
		tirePressure.RearRight = &pressureValue
		tirePressure.Timestamp = signal.Timestamp
	default:
		return tirePressure
	}

	return tirePressure
}

// categorizeDTCSeverity categorizes DTC severity based on the code.
func categorizeDTCSeverity(code string) string {
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
func isTirePressureNormal(tp *types.TirePressureStatus) bool {
	pressures := []*float64{tp.FrontLeft, tp.FrontRight, tp.RearLeft, tp.RearRight}

	for _, pressure := range pressures {
		if pressure != nil && (*pressure < minNormalTirePressure || *pressure > maxNormalTirePressure) {
			return false
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
