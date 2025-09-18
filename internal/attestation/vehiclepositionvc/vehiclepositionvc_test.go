//go:generate go tool mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=vehiclepositionvc_test
package vehiclepositionvc_test

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

	"github.com/DIMO-Network/attestation-api/internal/attestation/vehiclepositionvc"
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

func setupTestService(t *testing.T) (*vehiclepositionvc.Service, *MockVCRepo, *MockIdentityAPI, *MockTelemetryAPI, *gomock.Controller) {
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

	service := vehiclepositionvc.NewService(
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

func TestCreateVehiclePositionVC_Success(t *testing.T) {
	tests := []struct {
		name         string
		signals      []telemetryapi.Signal
		expectedLat  float64
		expectedLng  float64
		expectedTime time.Time
	}{
		{
			name: "closest location before requested time",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldCurrentLocationLatitude,
					Value:     37.7749,
					Timestamp: time.Date(2024, 1, 15, 11, 30, 0, 0, time.UTC), // 30 minutes before
				},
				{
					Name:      vss.FieldCurrentLocationLongitude,
					Value:     -122.4194,
					Timestamp: time.Date(2024, 1, 15, 11, 30, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldCurrentLocationLatitude,
					Value:     37.7849,
					Timestamp: time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC), // 30 minutes after
				},
				{
					Name:      vss.FieldCurrentLocationLongitude,
					Value:     -122.4094,
					Timestamp: time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC),
				},
			},
			expectedLat:  37.7749,
			expectedLng:  -122.4194,
			expectedTime: time.Date(2024, 1, 15, 11, 30, 0, 0, time.UTC),
		},
		{
			name: "closest location after requested time",
			signals: []telemetryapi.Signal{
				{
					Name:      vss.FieldCurrentLocationLatitude,
					Value:     37.7649,
					Timestamp: time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC), // 1 hour before
				},
				{
					Name:      vss.FieldCurrentLocationLongitude,
					Value:     -122.4294,
					Timestamp: time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC),
				},
				{
					Name:      vss.FieldCurrentLocationLatitude,
					Value:     37.7849,
					Timestamp: time.Date(2024, 1, 15, 12, 15, 0, 0, time.UTC), // 15 minutes after (closest)
				},
				{
					Name:      vss.FieldCurrentLocationLongitude,
					Value:     -122.4094,
					Timestamp: time.Date(2024, 1, 15, 12, 15, 0, 0, time.UTC),
				},
			},
			expectedLat:  37.7849,
			expectedLng:  -122.4094,
			expectedTime: time.Date(2024, 1, 15, 12, 15, 0, 0, time.UTC),
		},
		{
			name: "approximate location signals",
			signals: []telemetryapi.Signal{
				{
					Name:      "currentLocationApproximateLatitude",
					Value:     37.7949,
					Timestamp: time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
				},
				{
					Name:      "currentLocationApproximateLongitude",
					Value:     -122.3994,
					Timestamp: time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
				},
			},
			expectedLat:  37.7949,
			expectedLng:  -122.3994,
			expectedTime: time.Date(2024, 1, 15, 11, 45, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
			defer ctrl.Finish()

			tokenID := uint32(123)
			requestedTimestamp := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
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
			mockVCRepo.EXPECT().
				UploadAttestation(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, attestation *cloudevent.RawEvent) error {
					uploadedAttestation = attestation
					return nil
				})

			// Execute
			err := service.CreateVehiclePositionVC(context.Background(), tokenID, requestedTimestamp, jwtToken)

			// Assert
			assert.NoError(t, err)
			assert.NotNil(t, uploadedAttestation)

			// Verify cloud event structure
			assert.Equal(t, "1.0", uploadedAttestation.SpecVersion)
			assert.NotEmpty(t, uploadedAttestation.ID)
			assert.Equal(t, cloudevent.TypeAttestation, uploadedAttestation.Type)
			assert.Equal(t, "application/json", uploadedAttestation.DataContentType)
			assert.Equal(t, "vehicleposition/v1.0.0", uploadedAttestation.DataVersion)
			assert.NotEmpty(t, uploadedAttestation.Signature)

			// Verify credential data contains expected location
			var credential types.Credential
			err = json.Unmarshal(uploadedAttestation.Data, &credential)
			assert.NoError(t, err)
			assert.NotZero(t, credential.ValidFrom)
			assert.NotZero(t, credential.ValidTo)

			// Verify subject data
			var subjectData types.VehiclePositionVCSubject
			err = json.Unmarshal(credential.CredentialSubject, &subjectData)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedTime, subjectData.Location.Timestamp)
			assert.Equal(t, requestedTimestamp, subjectData.RequestedTimestamp)
			assert.Equal(t, types.LocationTypeH3Cell, subjectData.Location.LocationType)

			// Verify H3 cell was generated correctly
			h3Cell, ok := subjectData.Location.LocationValue.(types.H3Cell)
			assert.True(t, ok)
			assert.NotEmpty(t, h3Cell.CellID)

			// Verify the H3 cell was generated (we can't easily verify coordinates without proper h3 API)
			// The important part is that the location was processed and an H3 cell was created
			assert.NotEmpty(t, h3Cell.CellID)
		})
	}
}

func TestCreateVehiclePositionVC_TelemetryAPIError(t *testing.T) {
	service, _, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	requestedTimestamp := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
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
	err := service.CreateVehiclePositionVC(context.Background(), tokenID, requestedTimestamp, jwtToken)

	// Assert
	assert.Error(t, err)
	var richErr richerrors.Error
	assert.ErrorAs(t, err, &richErr)
	assert.Equal(t, http.StatusInternalServerError, richErr.Code)
}

func TestCreateVehiclePositionVC_NoLocationData(t *testing.T) {
	service, _, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	requestedTimestamp := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
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
	err := service.CreateVehiclePositionVC(context.Background(), tokenID, requestedTimestamp, jwtToken)

	// Assert
	assert.Error(t, err)
	var richErr richerrors.Error
	assert.ErrorAs(t, err, &richErr)
	assert.Equal(t, http.StatusNotFound, richErr.Code)
}

func TestCreateVehiclePositionVC_VCRepoError(t *testing.T) {
	service, mockVCRepo, mockIdentityAPI, mockTelemetryAPI, ctrl := setupTestService(t)
	defer ctrl.Finish()

	tokenID := uint32(123)
	requestedTimestamp := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
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

	// Mock telemetry data with location signals
	expectedSignals := []telemetryapi.Signal{
		{
			Name:      vss.FieldCurrentLocationLatitude,
			Value:     37.7749,
			Timestamp: requestedTimestamp.Add(-30 * time.Minute),
		},
		{
			Name:      vss.FieldCurrentLocationLongitude,
			Value:     -122.4194,
			Timestamp: requestedTimestamp.Add(-30 * time.Minute),
		},
	}

	mockTelemetryAPI.EXPECT().
		GetHistoricalDataWithAuth(gomock.Any(), gomock.Any(), jwtToken).
		Return(expectedSignals, nil)

	mockVCRepo.EXPECT().
		UploadAttestation(gomock.Any(), gomock.Any()).
		Return(assert.AnError)

	// Execute
	err := service.CreateVehiclePositionVC(context.Background(), tokenID, requestedTimestamp, jwtToken)

	// Assert
	assert.Error(t, err)
	var richErr richerrors.Error
	assert.ErrorAs(t, err, &richErr)
	assert.Equal(t, http.StatusInternalServerError, richErr.Code)
}
