package vc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	reflect "reflect"
	"strconv"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/controllers/vc"
	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
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
	var ctx = reflect.TypeOf((*context.Context)(nil)).Elem()
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
				tokenIDUint, _ := strconv.ParseUint("123", 10, 32)
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return([]models.PairedDevice{}, nil)
			},
			expectedStatusCode: fiber.StatusNotFound,
		},
		{
			name:    "valid request with paired devices",
			tokenID: "124",
			setupMocks: func(mocks Mocks) {
				tokenIDUint, _ := strconv.ParseUint("124", 10, 32)
				pairedDevices := []models.PairedDevice{
					{TokenID: uint32(tokenIDUint), Type: models.DeviceTypeAftermarket},
				}
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return(pairedDevices, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, uint32(tokenIDUint)).Return([]models.FingerprintMessage{
					{VIN: "1HGCM82633A123456", Timestamp: time.Now()},
				}, nil)
				mocks.VINService.EXPECT().ValidateVIN(ctxType, "1HGCM82633A123456").Return(nil)
				mocks.VCService.EXPECT().GenerateAndStoreVC(ctxType, gomock.Any(), uint32(tokenIDUint), gomock.Any(), gomock.Any(), "1HGCM82633A123456").Return(nil)
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
				tokenIDUint, _ := strconv.ParseUint("125", 10, 32)
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return(nil, errors.New("error"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},
		{
			name:    "no fingerprint messages",
			tokenID: "127",
			setupMocks: func(mocks Mocks) {
				tokenIDUint, _ := strconv.ParseUint("127", 10, 32)
				pairedDevices := []models.PairedDevice{
					{TokenID: uint32(tokenIDUint), Type: models.DeviceTypeAftermarket},
				}
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return(pairedDevices, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, uint32(tokenIDUint)).Return([]models.FingerprintMessage{}, fmt.Errorf("no fingerprint messages"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},
		{
			name:    "fingerprint messages with different VINs",
			tokenID: "128",
			setupMocks: func(mocks Mocks) {
				tokenIDUint, _ := strconv.ParseUint("128", 10, 32)
				pairedDevices := []models.PairedDevice{
					{TokenID: uint32(tokenIDUint), Type: models.DeviceTypeAftermarket},
					{TokenID: uint32(tokenIDUint + 1), Type: models.DeviceTypeSynthetic},
				}
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return(pairedDevices, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, uint32(tokenIDUint)).Return([]models.FingerprintMessage{
					{VIN: "1HGCM82633A123456", Timestamp: time.Now().Add(-1 * time.Hour)},
				}, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, uint32(tokenIDUint+1)).Return([]models.FingerprintMessage{
					{VIN: "1HGCM82633A654321", Timestamp: time.Now()},
				}, nil)
				mocks.VINService.EXPECT().ValidateVIN(ctxType, "1HGCM82633A654321").Return(nil)
				mocks.VCService.EXPECT().GenerateAndStoreVC(ctxType, gomock.Any(), uint32(tokenIDUint), gomock.Any(), gomock.Any(), "1HGCM82633A654321").Return(nil)
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name:    "invalid VIN from fingerprint message",
			tokenID: "129",
			setupMocks: func(mocks Mocks) {
				tokenIDUint, _ := strconv.ParseUint("129", 10, 32)
				pairedDevices := []models.PairedDevice{
					{TokenID: uint32(tokenIDUint), Type: models.DeviceTypeAftermarket},
				}
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return(pairedDevices, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, uint32(tokenIDUint)).Return([]models.FingerprintMessage{
					{VIN: "INVALIDVIN", Timestamp: time.Now()},
				}, nil)
				mocks.VINService.EXPECT().ValidateVIN(ctxType, "INVALIDVIN").Return(errors.New("invalid VIN"))
			},
			expectedStatusCode: fiber.StatusInternalServerError,
		},

		{
			name:    "error on generate and store VC",
			tokenID: "131",
			setupMocks: func(mocks Mocks) {
				tokenIDUint, _ := strconv.ParseUint("131", 10, 32)
				pairedDevices := []models.PairedDevice{
					{TokenID: uint32(tokenIDUint), Type: models.DeviceTypeAftermarket},
				}
				mocks.IdentityService.EXPECT().GetPairedDevices(ctxType, uint32(tokenIDUint)).Return(pairedDevices, nil)
				mocks.FingerprintService.EXPECT().GetLatestFingerprintMessages(ctxType, uint32(tokenIDUint)).Return([]models.FingerprintMessage{
					{VIN: "1HGCM82633A123456", Timestamp: time.Now()},
				}, nil)
				mocks.VINService.EXPECT().ValidateVIN(ctxType, "1HGCM82633A123456").Return(nil)
				mocks.VCService.EXPECT().GenerateAndStoreVC(ctxType, gomock.Any(), uint32(tokenIDUint), gomock.Any(), gomock.Any(), "1HGCM82633A123456").Return(errors.New("store error"))
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
				require.Contains(t, actualResponse, "vc_url")
				require.Contains(t, actualResponse, "vc_query")
				require.Contains(t, actualResponse, "message")
			}
		})
	}
}
