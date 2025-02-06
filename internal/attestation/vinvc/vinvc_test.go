package vinvc_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/vinvc"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	defaultNameSlug   = "toyota_tacoma-4wd_2023"
	defaultNFTAddress = "0x1234567890abcdef"
	polygonChainID    = 137
)

var testVCPayload = json.RawMessage(`{"test": "payload"}`)

type Mocks struct {
	issuer          *MockIssuer
	vcRepo          *MockVCRepo
	identityAPI     *MockIdentityAPI
	fingerprintRepo *MockFingerprintRepo
	vinAPI          *MockVINAPI
}

func TestVCController_GetVINVC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a new VCController instance with placeholder mocks
	logger := zerolog.New(httptest.NewRecorder())
	ctx := reflect.TypeOf((*context.Context)(nil)).Elem()
	ctxType := gomock.AssignableToTypeOf(ctx)
	tests := []struct {
		name           string
		tokenID        uint32
		setupMocks     func(mocks Mocks)
		expectedErrror bool
	}{
		{
			name:    "valid request with no paired devices",
			tokenID: 123,
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(123)
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
			},
			expectedErrror: true,
		},
		{
			name:    "valid request with paired devices",
			tokenID: 124,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(124)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}

				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
				validFP := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x123",
						Time:     time.Now(),
						Producer: pariedDevice.DID.String(),
					},
					VIN: "1HGCM82633A123456",
				}
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, pariedDevice).Return(&validFP, nil)
				mocks.vinAPI.EXPECT().DecodeVIN(ctxType, validFP.VIN, "").Return(vehicleInfo.NameSlug, nil)
				vinSubject := verifiable.VINSubject{
					VehicleIdentificationNumber: validFP.VIN,
					VehicleTokenID:              tokenID,
					CountryCode:                 "",
					RecordedBy:                  validFP.Producer,
					RecordedAt:                  validFP.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.issuer.EXPECT().CreateVINVC(vinSubject, gomock.Any()).Return(testVCPayload, nil)
				mocks.vcRepo.EXPECT().StoreVINVC(ctxType, vehicleInfo.DID.String(), pariedDevice.DID.String(), testVCPayload).Return(nil)
			},
		},
		{
			name:    "error fetching paired devices",
			tokenID: 125,
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(125)
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(nil, errors.New("error"))
			},
			expectedErrror: true,
		},
		{
			name:    "no fingerprint messages",
			tokenID: 127,
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(127)
				pairedAddr := randAddress()
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, pariedDevice).Return(nil, fmt.Errorf("no fingerprint messages"))
			},
			expectedErrror: true,
		},
		{
			name:    "fingerprint messages with different VINs",
			tokenID: 128,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				pairedAddr2 := randAddress()
				tokenID := uint32(128)
				device1 := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				device2 := models.PairedDevice{
					Address: pairedAddr2.String(),
					Type:    models.DeviceTypeSynthetic,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         11,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{device1, device2},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)

				validFPEarliest := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x123",
						Time:     time.Now().Add(-1 * time.Hour),
						Producer: device1.DID.String(),
					},
					VIN: "1HGCM82633A123456",
				}
				validFPLatest := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x456",
						Time:     time.Now(),
						Producer: device2.DID.String(),
					},
					VIN: "1HGCM82633A654321",
				}

				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, device1).Return(&validFPEarliest, nil)
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, device2).Return(&validFPLatest, nil)
				mocks.vinAPI.EXPECT().DecodeVIN(ctxType, validFPLatest.VIN, "").Return(vehicleInfo.NameSlug, nil)

				vinSubject := verifiable.VINSubject{
					VehicleIdentificationNumber: validFPLatest.VIN,
					VehicleTokenID:              tokenID,
					CountryCode:                 "",
					RecordedBy:                  validFPLatest.Producer,
					RecordedAt:                  validFPLatest.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.issuer.EXPECT().CreateVINVC(vinSubject, gomock.Any()).Return(testVCPayload, nil)
				mocks.vcRepo.EXPECT().StoreVINVC(ctxType, vehicleInfo.DID.String(), device2.DID.String(), testVCPayload).Return(nil)
			},
		},
		{
			name:    "failed to decode VIN from fingerprint message",
			tokenID: 129,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(129)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
				invalidFP := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x123",
						Time:     time.Now(),
						Producer: pariedDevice.DID.String(),
					},
					VIN: "INVALIDVIN",
				}
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, pariedDevice).Return(&invalidFP, nil)
				mocks.vinAPI.EXPECT().DecodeVIN(ctxType, "INVALIDVIN", "").Return("", errors.New("invalid VIN"))
			},
			expectedErrror: true,
		},
		{
			name:    "invalid VIN from fingerprint message",
			tokenID: 130,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(130)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
				validFP := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x123",
						Time:     time.Now(),
						Producer: pariedDevice.DID.String(),
					},
					VIN: "1HGCM82633A123456",
				}
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, pariedDevice).Return(&validFP, nil)
				mocks.vinAPI.EXPECT().DecodeVIN(ctxType, "1HGCM82633A123456", "").Return("bad_name", nil)
			},
			expectedErrror: true,
		},
		{
			name:    "error on generate and store VC",
			tokenID: 131,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := uint32(131)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(nil, sql.ErrNoRows)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
				validFP := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x123",
						Time:     time.Now(),
						Producer: pariedDevice.DID.String(),
					},
					VIN: "1HGCM82633A123456",
				}
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, pariedDevice).Return(&validFP, nil)
				mocks.vinAPI.EXPECT().DecodeVIN(ctxType, validFP.VIN, "").Return(vehicleInfo.NameSlug, nil)
				vinSubject := verifiable.VINSubject{
					VehicleIdentificationNumber: validFP.VIN,
					VehicleTokenID:              tokenID,
					CountryCode:                 "",
					RecordedBy:                  validFP.Producer,
					RecordedAt:                  validFP.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.issuer.EXPECT().CreateVINVC(vinSubject, gomock.Any()).Return(nil, errors.New("store error"))
			},
			expectedErrror: true,
		},
		{
			name:    "VC already exists",
			tokenID: 132,
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(132)
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(&verifiable.Credential{
					ValidFrom: time.Now().Add(time.Hour).Format(time.RFC3339),
				}, nil)
			},
		},
		{
			name:    "VC is expired",
			tokenID: 133,
			setupMocks: func(mocks Mocks) {
				tokenID := uint32(133)
				pairedAddr := randAddress()
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.NFTDID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.vcRepo.EXPECT().GetLatestVINVC(ctxType, vehicleInfo.DID).Return(&verifiable.Credential{
					ValidFrom: time.Now().Add(-time.Hour).Format(time.RFC3339),
				}, nil)
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
				validFP := models.DecodedFingerprintData{
					CloudEventHeader: cloudevent.CloudEventHeader{
						Source:   "0x123",
						Time:     time.Now(),
						Producer: pariedDevice.DID.String(),
					},
					VIN: "1HGCM82633A123456",
				}
				mocks.fingerprintRepo.EXPECT().GetLatestFingerprintMessages(ctxType, vehicleInfo.DID, pariedDevice).Return(&validFP, nil)
				mocks.vinAPI.EXPECT().DecodeVIN(ctxType, validFP.VIN, "").Return(vehicleInfo.NameSlug, nil)
				vinSubject := verifiable.VINSubject{
					VehicleIdentificationNumber: validFP.VIN,
					VehicleTokenID:              tokenID,
					CountryCode:                 "",
					RecordedBy:                  validFP.Producer,
					RecordedAt:                  validFP.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.issuer.EXPECT().CreateVINVC(vinSubject, gomock.Any()).Return(testVCPayload, nil)
				mocks.vcRepo.EXPECT().StoreVINVC(ctxType, vehicleInfo.DID.String(), pariedDevice.DID.String(), testVCPayload).Return(nil)
			},
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			// Initialize mocks for this specific test case
			mocks := Mocks{
				issuer:          NewMockIssuer(ctrl),
				vcRepo:          NewMockVCRepo(ctrl),
				identityAPI:     NewMockIdentityAPI(ctrl),
				fingerprintRepo: NewMockFingerprintRepo(ctrl),
				vinAPI:          NewMockVINAPI(ctrl),
			}

			// Set up the mocks as defined in the test case
			tt.setupMocks(mocks)

			// Create a new VCController instance for this test
			vcController := vinvc.NewService(&logger,
				mocks.vcRepo, mocks.identityAPI,
				mocks.fingerprintRepo, mocks.vinAPI,
				mocks.issuer, nil, defaultNFTAddress,
				polygonChainID,
			)

			err := vcController.GetOrCreateVC(context.Background(), tt.tokenID, false)
			if tt.expectedErrror {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
