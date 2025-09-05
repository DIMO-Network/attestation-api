//go:generate go tool mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=vehiclehealthvc_test
package vehiclehealthvc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/vehiclehealthvc"
	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupTestService(t *testing.T) (*vehiclehealthvc.Service, *MockVCRepo, *MockIdentityAPI, *MockTelemetryAPI, *gomock.Controller) {
	ctrl := gomock.NewController(t)

	mockVCRepo := NewMockVCRepo(ctrl)
	mockIdentityAPI := NewMockIdentityAPI(ctrl)
	mockTelemetryAPI := NewMockTelemetryAPI(ctrl)

	settings := &config.Settings{
		VehicleNFTAddress:   "0x1234567890123456789012345678901234567890",
		DIMORegistryChainID: 137,
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	service := vehiclehealthvc.NewService(
		mockVCRepo,
		mockIdentityAPI,
		mockTelemetryAPI,
		settings,
		privateKey,
	)

	return service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl
}

func TestNewService(t *testing.T) {
	service, _, _, _, ctrl := setupTestService(t)
	defer ctrl.Finish()

	// Assert
	assert.NotNil(t, service)
}

func TestCreateVehicleHealthVC_Success(t *testing.T) {
	tests := []struct {
		name                string
		signals             []telemetryapi.Signal
		expectedDTCs        int
		expectedHealthScore int
		expectedIsHealthy   bool
		expectedTireNormal  bool
	}{
		{
			name: "healthy vehicle with normal tire pressure",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldOBDDTCList,
					Value:     `[]`,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldOBDStatusDTCCount,
					Value:     0.0,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelLeftTirePressure,
					Value:     220.0, // Normal pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelRightTirePressure,
					Value:     230.0, // Normal pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
			},
			expectedDTCs:        0,
			expectedHealthScore: 100,
			expectedIsHealthy:   true,
			expectedTireNormal:  true,
		},
		{
			name: "vehicle with warning DTCs and normal tire pressure",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldOBDDTCList,
					Value:     `["P0301", "P0171"]`,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldOBDStatusDTCCount,
					Value:     2.0,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelLeftTirePressure,
					Value:     220.0, // Normal pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelRightTirePressure,
					Value:     230.0, // Normal pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
			},
			expectedDTCs:        3,  // 2 from DTC list + 1 from DTC count
			expectedHealthScore: 85, // 100 - 15 (warning DTC) - 15 (warning DTC) - 5 (info DTC)
			expectedIsHealthy:   true,
			expectedTireNormal:  true,
		},
		{
			name: "vehicle with critical DTCs and low tire pressure",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldOBDDTCList,
					Value:     `["P0100", "P0200"]`,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldOBDStatusDTCCount,
					Value:     2.0,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelLeftTirePressure,
					Value:     180.0, // Low pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelRightTirePressure,
					Value:     220.0, // Normal pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
			},
			expectedDTCs:        3,  // 2 from DTC list + 1 from DTC count
			expectedHealthScore: 20, // 100 - 30 (critical) - 30 (critical) - 5 (info) - 20 (tire pressure)
			expectedIsHealthy:   false,
			expectedTireNormal:  false,
		},
		{
			name: "vehicle with only tire pressure issues",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldOBDDTCList,
					Value:     `[]`,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldOBDStatusDTCCount,
					Value:     0.0,
					Timestamp: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelLeftTirePressure,
					Value:     180.0, // Low pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldChassisAxleRow1WheelRightTirePressure,
					Value:     300.0, // High pressure
					Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
				},
			},
			expectedDTCs:        0,
			expectedHealthScore: 80, // 100 - 20 (tire pressure)
			expectedIsHealthy:   true,
			expectedTireNormal:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockVCRepo, _, mockTelemetryAPI, ctrl := setupTestService(t)
			defer ctrl.Finish()

			tokenID := uint32(123)
			startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			endTime := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
			jwtToken := "test-jwt-token"

			mockTelemetryAPI.EXPECT().
				GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
				Return(tt.signals, nil)

			// Capture the uploaded attestation for verification
			var uploadedAttestation *cloudevent.RawEvent
			mockVCRepo.EXPECT().
				UploadAttestation(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, attestation *cloudevent.RawEvent) error {
					uploadedAttestation = attestation
					return nil
				})

			// Execute
			err := service.CreateVehicleHealthVC(context.Background(), tokenID, startTime, endTime, jwtToken)

			// Assert
			assert.NoError(t, err)
			assert.NotNil(t, uploadedAttestation)

			// Verify cloud event structure
			assert.Equal(t, "1.0", uploadedAttestation.SpecVersion)
			assert.NotEmpty(t, uploadedAttestation.ID)
			assert.Equal(t, cloudevent.TypeAttestation, uploadedAttestation.Type)
			assert.Equal(t, "application/json", uploadedAttestation.DataContentType)
			assert.Equal(t, "1.0.0", uploadedAttestation.DataVersion)
			assert.NotEmpty(t, uploadedAttestation.Signature)

			// Verify credential data contains expected health status
			var credential types.Credential
			err = json.Unmarshal(uploadedAttestation.Data, &credential)
			assert.NoError(t, err)
			assert.NotZero(t, credential.ValidFrom)
			assert.NotZero(t, credential.ValidTo)

			// Verify subject data
			var subjectData types.VehicleHealthVCSubject
			err = json.Unmarshal(credential.CredentialSubject, &subjectData)
			assert.NoError(t, err)
			assert.Len(t, subjectData.HealthStatus.DTCs, tt.expectedDTCs)
			assert.Equal(t, tt.expectedTireNormal, subjectData.HealthStatus.TirePressure.IsNormal)
			assert.Equal(t, startTime, subjectData.SearchedTimeRange.Start)
			assert.Equal(t, endTime, subjectData.SearchedTimeRange.End)
		})
	}
}

func TestCreateVehicleHealthVC_TelemetryAPIError(t *testing.T) {
	service, _, _, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	jwtToken := "test-jwt-token"

	// Mock telemetry API error
	mockTelemetryAPI.EXPECT().
		GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
		Return(nil, assert.AnError)

	// Execute
	err := service.CreateVehicleHealthVC(context.Background(), tokenID, startTime, endTime, jwtToken)

	// Assert
	assert.Error(t, err)
	var richErr richerrors.Error
	assert.ErrorAs(t, err, &richErr)
	assert.Equal(t, "Failed to analyze vehicle health", richErr.ExternalMsg)
}

func TestCreateVehicleHealthVC_NoHealthData(t *testing.T) {
	service, _, _, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	jwtToken := "test-jwt-token"

	// Mock empty telemetry data
	mockTelemetryAPI.EXPECT().
		GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
		Return([]telemetryapi.Signal{}, nil)

	// Execute
	err := service.CreateVehicleHealthVC(context.Background(), tokenID, startTime, endTime, jwtToken)

	// Assert
	assert.Error(t, err)
	var richErr richerrors.Error
	assert.ErrorAs(t, err, &richErr)
	assert.Equal(t, "Failed to analyze vehicle health", richErr.ExternalMsg)
}

func TestCreateVehicleHealthVC_VCRepoError(t *testing.T) {
	service, mockVCRepo, _, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	jwtToken := "test-jwt-token"

	// Mock telemetry data with health signals
	expectedSignals := []telemetryapi.Signal{
		{
			Name:      vss.FieldOBDDTCList,
			Value:     `["P0301"]`,
			Timestamp: startTime.Add(1 * time.Hour),
		},
	}

	mockTelemetryAPI.EXPECT().
		GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
		Return(expectedSignals, nil)

	mockVCRepo.EXPECT().
		UploadAttestation(gomock.Any(), gomock.Any()).
		Return(assert.AnError)

	// Execute
	err := service.CreateVehicleHealthVC(context.Background(), tokenID, startTime, endTime, jwtToken)

	// Assert
	assert.Error(t, err)
	var richErr richerrors.Error
	assert.ErrorAs(t, err, &richErr)
	assert.Equal(t, "Failed to store VehicleHealthVC", richErr.ExternalMsg)
}
