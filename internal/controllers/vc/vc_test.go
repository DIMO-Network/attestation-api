package vc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/controllers/vc"
	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	defaultNameSlug = "toyota_tacoma-4wd_2023"
)

type Mocks struct {
	VCService          *MockVCService
	IdentityService    *MockIdentityService
	FingerprintService *MockFingerprintService
	VINService         *MockVINService
}

func TestVCController_GetVINVC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a new VCController instance with placeholder mocks
	telemetryURL := "https://telemetry-api.example.com/vc"
	logger := zerolog.New(httptest.NewRecorder())
	ctx := reflect.TypeOf((*context.Context)(nil)).Elem()
	ctxType := gomock.AssignableToTypeOf(ctx)
	tests := []struct {
		name               string
		tokenID            string
		setupMocks         func(mocks Mocks)
		expectedStatusCode int
	}{
		{
			name:    "valid request with no paired devices",
			tokenID: "123",
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(123)
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(&models.VehicleInfo{}, nil)
			},
			expectedStatusCode: fiber.StatusBadRequest,
		},
		{
			name:    "valid request with paired devices",
			tokenID: "124",
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(124)
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{Address: pairedAddr, Type: models.DeviceTypeAftermarket},
					},
					NameSlug: defaultNameSlug,
				}
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(vehicleInfo, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, pairedAddr).Return(&models.DecodedFingerprintData{
					VIN: "1HGCM82633A123456", Timestamp: time.Now(),
				}, nil)
				mocks.VINService.EXPECT().DecodeVIN(ctxType, "1HGCM82633A123456", "").Return(vehicleInfo.NameSlug, nil)
				mocks.VCService.EXPECT().GenerateAndStoreVINVC(ctxType, tokenID, "1HGCM82633A123456", "").Return(nil)
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name:    "invalid token_id format",
			tokenID: "invalid_token_id",
			setupMocks: func(mocks Mocks) {
				// No mocks needed for this case
			},
			expectedStatusCode: fiber.StatusBadRequest,
		},
		{
			name:    "error fetching paired devices",
			tokenID: "125",
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(125)
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(nil, errors.New("error"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},
		{
			name:    "no fingerprint messages",
			tokenID: "127",
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(127)
				pairedAddr := randAddress()
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{Address: pairedAddr, Type: models.DeviceTypeAftermarket},
					},
					NameSlug: defaultNameSlug,
				}
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(vehicleInfo, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, pairedAddr).Return(&models.DecodedFingerprintData{}, fmt.Errorf("no fingerprint messages"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},
		{
			name:    "fingerprint messages with different VINs",
			tokenID: "128",
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				pairedAddr2 := randAddress()
				tokenID := uint32(128)
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{Address: pairedAddr, Type: models.DeviceTypeAftermarket},
						{Address: pairedAddr2, Type: models.DeviceTypeSynthetic},
					},
					NameSlug: defaultNameSlug,
				}
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(vehicleInfo, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, pairedAddr).Return(&models.DecodedFingerprintData{
					VIN: "1HGCM82633A123456", Timestamp: time.Now().Add(-1 * time.Hour),
				}, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, pairedAddr2).Return(&models.DecodedFingerprintData{
					VIN: "1HGCM82633A654321", Timestamp: time.Now(),
				}, nil)
				mocks.VINService.EXPECT().DecodeVIN(ctxType, "1HGCM82633A654321", "").Return(vehicleInfo.NameSlug, nil)
				mocks.VCService.EXPECT().GenerateAndStoreVINVC(ctxType, tokenID, "1HGCM82633A654321", "").Return(nil)
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name:    "invalid VIN from fingerprint message",
			tokenID: "129",
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(129)
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{Address: pairedAddr, Type: models.DeviceTypeAftermarket},
					},
					NameSlug: defaultNameSlug,
				}
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(vehicleInfo, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, pairedAddr).Return(&models.DecodedFingerprintData{
					VIN: "INVALIDVIN", Timestamp: time.Now(),
				}, nil)
				mocks.VINService.EXPECT().DecodeVIN(ctxType, "INVALIDVIN", "").Return("", errors.New("invalid VIN"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},

		{
			name:    "error on generate and store VC",
			tokenID: "131",
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(131)
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{
						{Address: pairedAddr, Type: models.DeviceTypeAftermarket},
					},
					NameSlug: defaultNameSlug,
				}
				mocks.IdentityService.EXPECT().GetVehicleInfo(ctxType, tokenID).Return(vehicleInfo, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, pairedAddr).Return(&models.DecodedFingerprintData{
					VIN: "1HGCM82633A123456", Timestamp: time.Now(),
				}, nil)
				mocks.VINService.EXPECT().DecodeVIN(ctxType, "1HGCM82633A123456", "").Return(vehicleInfo.NameSlug, nil)
				mocks.VCService.EXPECT().GenerateAndStoreVINVC(ctxType, tokenID, "1HGCM82633A123456", "").Return(errors.New("store error"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},
		// Add more test cases as needed
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Initialize mocks for this specific test case
			mocks := Mocks{
				VCService:          NewMockVCService(ctrl),
				IdentityService:    NewMockIdentityService(ctrl),
				FingerprintService: NewMockFingerprintService(ctrl),
				VINService:         NewMockVINService(ctrl),
			}

			// Create a new VCController instance for this test
			vcController, err := vc.NewVCController(&logger, mocks.VCService, mocks.IdentityService, mocks.FingerprintService, mocks.VINService, telemetryURL)
			require.NoError(t, err)

			// Set up the mocks as defined in the test case
			tt.setupMocks(mocks)

			// Register the handler
			app := fiber.New()
			app.Get("/v1/vc/vin", vcController.GetVINVC)

			// Create a test request
			req := httptest.NewRequest(http.MethodGet, "/v1/vc/vin?token_id="+tt.tokenID, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			require.Equal(t, tt.expectedStatusCode, resp.StatusCode)

			if tt.expectedStatusCode == fiber.StatusOK {
				// Read and check the response body
				bodyBytes, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				var actualResponse map[string]interface{}
				err = json.Unmarshal(bodyBytes, &actualResponse)
				require.NoError(t, err)

				// Check for the presence of the required fields
				require.Contains(t, actualResponse, "vcUrl")
				require.Contains(t, actualResponse, "vcQuery")
				require.Contains(t, actualResponse, "message")
			}
		})
	}
}

func randAddress() common.Address {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	return crypto.PubkeyToAddress(privateKey.PublicKey)
}
