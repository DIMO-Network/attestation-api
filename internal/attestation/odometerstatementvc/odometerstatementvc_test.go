//go:generate go tool mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=odometerstatementvc_test
package odometerstatementvc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/odometerstatementvc"
	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupTestService(t *testing.T) (*odometerstatementvc.Service, *MockVCRepo, *MockIdentityAPI, *MockTelemetryAPI, *gomock.Controller) {
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

	service := odometerstatementvc.NewService(
		mockVCRepo,
		mockIdentityAPI,
		mockTelemetryAPI,
		settings,
		privateKey,
	)

	return service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl
}

func TestCreateOdometerStatementVC_WithTimestamp(t *testing.T) {
	requestedTime := time.Date(2024, 12, 23, 12, 34, 56, 0, time.UTC)
	tests := []struct {
		name          string
		signals       []telemetryapi.Signal
		expectedValue float64
		expectedUnit  string
		expectedTime  time.Time
		expectedError bool
	}{
		{
			name: "closest signal before requested time",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     50000.0,
					Timestamp: requestedTime.Add(-30 * time.Minute),
				},
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     50010.0,
					Timestamp: requestedTime.Add(31 * time.Minute),
				},
			},
			expectedValue: 50000.0,
			expectedUnit:  "km",
			expectedTime:  requestedTime.Add(-30 * time.Minute),
		},
		{
			name: "closest signal after requested time",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     50000.0,
					Timestamp: requestedTime.Add(-1 * time.Hour),
				},
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     60010.0,
					Timestamp: requestedTime.Add(15 * time.Minute),
				},
			},
			expectedValue: 60010.0,
			expectedUnit:  "km",
			expectedTime:  requestedTime.Add(15 * time.Minute),
		},
		{
			name: "closest signal is non odometer signal",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     50000.0,
					Timestamp: requestedTime.Add(-1 * time.Hour),
				},
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     50010.0,
					Timestamp: requestedTime.Add(15 * time.Minute),
				},
				{
					Name:      vss.FieldSpeed,
					Value:     50020.0,
					Timestamp: requestedTime,
				},
			},
			expectedValue: 50010.0,
			expectedUnit:  "km",
			expectedTime:  requestedTime.Add(15 * time.Minute),
		},
		{
			name: "signal is 0 value",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     0.0,
					Timestamp: requestedTime,
				},
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     10.0,
					Timestamp: requestedTime.Add(15 * time.Minute),
				},
			},
			expectedValue: 10.0,
			expectedUnit:  "km",
			expectedTime:  requestedTime.Add(15 * time.Minute),
		},
		{
			name: "single signal",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     75000.0,
					Timestamp: time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
				},
			},
			expectedValue: 75000.0,
			expectedUnit:  "km",
			expectedTime:  time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
		},
		{
			name: "no odometer data",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldSpeed,
					Value:     50.0,
					Timestamp: requestedTime,
				},
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
			defer ctrl.Finish()

			tokenID := uint32(123)
			jwtToken := "test-jwt-token"

			// Mock GetVehicleInfo call for producer information
			mockIdentityAPI.EXPECT().
				GetVehicleInfo(gomock.Any(), gomock.Any()).
				Return(&models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{
							DID:  cloudevent.ERC721DID{TokenID: big.NewInt(456), ChainID: 137, ContractAddress: common.HexToAddress("0xabcd")},
							Type: models.DeviceTypeAftermarket,
						},
					},
				}, nil)

			mockTelemetryAPI.EXPECT().
				GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
				Return(tt.signals, nil)

			// Capture the uploaded attestation for verification
			var uploadedAttestation *cloudevent.RawEvent
			if !tt.expectedError {
				mockVCRepo.EXPECT().
					UploadAttestation(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, attestation *cloudevent.RawEvent) error {
						uploadedAttestation = attestation
						return nil
					})
			}

			// Execute
			err := service.CreateOdometerStatementVC(context.Background(), tokenID, &requestedTime, jwtToken)
			if tt.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, uploadedAttestation)

			// Verify cloud event structure
			assert.NotEmpty(t, uploadedAttestation.ID)
			assert.NotEmpty(t, uploadedAttestation.Source)
			assert.Equal(t, cloudevent.TypeAttestation, uploadedAttestation.Type)
			assert.Equal(t, "application/json", uploadedAttestation.DataContentType)
			assert.NotEmpty(t, uploadedAttestation.Signature)

			// Verify credential data contains expected odometer reading
			var credential types.Credential
			err = json.Unmarshal(uploadedAttestation.Data, &credential)
			require.NoError(t, err)
			assert.NotZero(t, credential.ValidFrom)
			assert.NotZero(t, credential.ValidTo)

			// Verify subject data
			var subjectData types.OdometerStatementVCSubject
			err = json.Unmarshal(credential.CredentialSubject, &subjectData)
			require.NoError(t, err)
			assert.InEpsilon(t, tt.expectedValue, subjectData.OdometerReading.Value, 0.000001)
			assert.Equal(t, tt.expectedUnit, subjectData.OdometerReading.Unit)
			assert.Equal(t, tt.expectedTime, subjectData.OdometerReading.Timestamp)
			assert.Equal(t, &requestedTime, subjectData.RequestedTimestamp)
		})
	}
}

func TestCreateOdometerStatementVC_WithoutTimestamp(t *testing.T) {
	tests := []struct {
		name          string
		signals       []telemetryapi.Signal
		expectedValue float64
		expectedUnit  string
		expectedTime  time.Time
		expectedError bool
	}{
		{
			name: "single latest odometer",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldPowertrainTransmissionTravelledDistance,
					Value:     75000.0,
					Timestamp: time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
				},
			},
			expectedValue: 75000.0,
			expectedUnit:  "km",
			expectedTime:  time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
		},
		{
			name: "no odometer data",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldSpeed,
					Value:     50.0,
					Timestamp: time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
				},
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
			defer ctrl.Finish()

			tokenID := uint32(123)
			jwtToken := "test-jwt-token"

			// Mock GetVehicleInfo call for producer information
			mockIdentityAPI.EXPECT().
				GetVehicleInfo(gomock.Any(), gomock.Any()).
				Return(&models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{
							DID:  cloudevent.ERC721DID{TokenID: big.NewInt(456), ChainID: 137, ContractAddress: common.HexToAddress("0xabcd")},
							Type: models.DeviceTypeAftermarket,
						},
					},
				}, nil)

			mockTelemetryAPI.EXPECT().
				GetLatestSignalsWithAuth(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, options telemetryapi.TelemetryLatestOptions) ([]telemetryapi.Signal, error) {
				require.Equal(t, uint64(tokenID), options.TokenID.Uint64())
				require.Equal(t, jwtToken, options.JWTToken)
				require.Equal(t, []string{vss.FieldPowertrainTransmissionTravelledDistance}, options.Signals)
				return tt.signals, nil
			})

			var uploadedAttestation *cloudevent.RawEvent
			if !tt.expectedError {
				mockVCRepo.EXPECT().
					UploadAttestation(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, attestation *cloudevent.RawEvent) error {
						uploadedAttestation = attestation
						return nil
					})
			}

			// Execute
			err := service.CreateOdometerStatementVC(context.Background(), tokenID, nil, jwtToken)
			if tt.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, uploadedAttestation)

			// Verify cloud event structure
			assert.NotEmpty(t, uploadedAttestation.ID)
			assert.NotEmpty(t, uploadedAttestation.Source)
			assert.Equal(t, cloudevent.TypeAttestation, uploadedAttestation.Type)
			assert.Equal(t, "application/json", uploadedAttestation.DataContentType)
			assert.NotEmpty(t, uploadedAttestation.Signature)

			// Verify credential data contains expected odometer reading
			var credential types.Credential
			err = json.Unmarshal(uploadedAttestation.Data, &credential)
			require.NoError(t, err)
			assert.NotZero(t, credential.ValidFrom)
			assert.NotZero(t, credential.ValidTo)

			// Verify subject data
			var subjectData types.OdometerStatementVCSubject
			err = json.Unmarshal(credential.CredentialSubject, &subjectData)
			require.NoError(t, err)
			assert.InEpsilon(t, tt.expectedValue, subjectData.OdometerReading.Value, 0.000001)
			assert.Equal(t, tt.expectedUnit, subjectData.OdometerReading.Unit)
			assert.Equal(t, tt.expectedTime, subjectData.OdometerReading.Timestamp)
			assert.Nil(t, subjectData.RequestedTimestamp)
		})
	}
}

func TestCreateOdometerStatementVC_TelemetryAPIError(t *testing.T) {
	service, _, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	requestedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	jwtToken := "test-jwt-token"

	// Mock GetVehicleInfo call for producer information
	mockIdentityAPI.EXPECT().
		GetVehicleInfo(gomock.Any(), gomock.Any()).
		Return(&models.VehicleInfo{
			PairedDevices: []models.PairedDevice{
				{
					DID:  cloudevent.ERC721DID{TokenID: big.NewInt(456), ChainID: 137, ContractAddress: common.HexToAddress("0xabcd")},
					Type: models.DeviceTypeAftermarket,
				},
			},
		}, nil)

	// Mock telemetry API error
	mockTelemetryAPI.EXPECT().
		GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
		Return(nil, assert.AnError)

	// Execute
	err := service.CreateOdometerStatementVC(context.Background(), tokenID, &requestedTime, jwtToken)

	// Assert
	assert.Error(t, err)
	var ctrlErr richerrors.Error
	assert.ErrorAs(t, err, &ctrlErr)
	assert.Equal(t, http.StatusInternalServerError, ctrlErr.Code)
}

func TestCreateOdometerStatementVC_NoOdometerData(t *testing.T) {
	service, _, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	requestedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	jwtToken := "test-jwt-token"

	// Mock GetVehicleInfo call for producer information
	mockIdentityAPI.EXPECT().
		GetVehicleInfo(gomock.Any(), gomock.Any()).
		Return(&models.VehicleInfo{
			PairedDevices: []models.PairedDevice{
				{
					DID:  cloudevent.ERC721DID{TokenID: big.NewInt(456), ChainID: 137, ContractAddress: common.HexToAddress("0xabcd")},
					Type: models.DeviceTypeAftermarket,
				},
			},
		}, nil)

	// Mock empty telemetry data
	mockTelemetryAPI.EXPECT().
		GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
		Return([]telemetryapi.Signal{}, nil)

	// Execute
	err := service.CreateOdometerStatementVC(context.Background(), tokenID, &requestedTime, jwtToken)

	// Assert
	assert.Error(t, err)
	var ctrlErr richerrors.Error
	assert.ErrorAs(t, err, &ctrlErr)
	assert.Equal(t, http.StatusNotFound, ctrlErr.Code)
}

func TestCreateOdometerStatementVC_VCRepoError(t *testing.T) {
	service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	jwtToken := "test-jwt-token"
	tokenID := uint32(123)

	// Mock GetVehicleInfo call for producer information
	mockIdentityAPI.EXPECT().
		GetVehicleInfo(gomock.Any(), gomock.Any()).
		Return(&models.VehicleInfo{
			PairedDevices: []models.PairedDevice{
				{
					DID:  cloudevent.ERC721DID{TokenID: big.NewInt(456), ChainID: 137, ContractAddress: common.HexToAddress("0xabcd")},
					Type: models.DeviceTypeAftermarket,
				},
			},
		}, nil)

	// Mock telemetry data
	expectedSignals := []telemetryapi.Signal{
		{
			Name:      vss.FieldPowertrainTransmissionTravelledDistance,
			Value:     50000.0,
			Timestamp: time.Now().Add(-1 * time.Hour),
		},
	}

	mockTelemetryAPI.EXPECT().
		GetLatestSignalsWithAuth(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, options telemetryapi.TelemetryLatestOptions) ([]telemetryapi.Signal, error) {
		require.Equal(t, uint64(tokenID), options.TokenID.Uint64())
		require.Equal(t, jwtToken, options.JWTToken)
		require.Equal(t, []string{vss.FieldPowertrainTransmissionTravelledDistance}, options.Signals)
		return expectedSignals, nil
	})

	mockVCRepo.EXPECT().
		UploadAttestation(gomock.Any(), gomock.Any()).
		Return(assert.AnError)

	// Execute
	err := service.CreateOdometerStatementVC(context.Background(), tokenID, nil, jwtToken)

	// Assert
	assert.Error(t, err)
	var ctrlErr richerrors.Error
	assert.ErrorAs(t, err, &ctrlErr)
	assert.Equal(t, http.StatusInternalServerError, ctrlErr.Code)
}
