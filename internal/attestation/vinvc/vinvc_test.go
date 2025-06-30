//go:generate go tool mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=vinvc_test
package vinvc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/vinvc"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
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

var testVCPayload = &cloudevent.RawEvent{
	CloudEventHeader: cloudevent.CloudEventHeader{
		Source: "0x123",
		Time:   time.Now(),
	},
	Data: json.RawMessage(`{"test": "payload"}`),
}

type Mocks struct {
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
	tokenID10 := new(big.Int).SetInt64(10)
	tests := []struct {
		name           string
		tokenID        uint32
		before         time.Time
		setupMocks     func(mocks Mocks)
		expectedErrror bool
	}{
		{
			name:    "valid request with no paired devices",
			tokenID: 123,
			setupMocks: func(mocks Mocks) {
				tokenID := big.NewInt(123)
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(vehicleInfo, nil)
			},
			expectedErrror: true,
		},
		{
			name:    "valid request with paired devices",
			tokenID: 124,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := big.NewInt(124)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}

				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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

				// Create a matcher to verify the expected VIN subject
				expectedVINSubject := models.VINSubject{
					VehicleDID:                  vehicleInfo.DID.String(),
					VehicleIdentificationNumber: validFP.VIN,
					VehicleTokenID:              uint32(tokenID.Uint64()),
					CountryCode:                 "",
					RecordedBy:                  validFP.Producer,
					RecordedAt:                  validFP.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.vcRepo.EXPECT().UploadAttestation(ctxType, matchVINSubject(expectedVINSubject)).Return(nil)
			},
		},
		{
			name:    "error fetching paired devices",
			tokenID: 125,
			setupMocks: func(mocks Mocks) {
				tokenID := big.NewInt(125)
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				mocks.identityAPI.EXPECT().GetVehicleInfo(ctxType, vehicleInfo.DID).Return(nil, errors.New("error"))
			},
			expectedErrror: true,
		},
		{
			name:    "no fingerprint messages",
			tokenID: 127,
			setupMocks: func(mocks Mocks) {
				tokenID := big.NewInt(127)
				pairedAddr := randAddress()
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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
				tokenID := big.NewInt(128)
				device1 := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				device2 := models.PairedDevice{
					Address: pairedAddr2.String(),
					Type:    models.DeviceTypeSynthetic,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         big.NewInt(11),
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{device1, device2},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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

				// Create a matcher to verify the expected VIN subject (should use the latest fingerprint)
				expectedVINSubject := models.VINSubject{
					VehicleDID:                  vehicleInfo.DID.String(),
					VehicleIdentificationNumber: validFPLatest.VIN,
					VehicleTokenID:              uint32(tokenID.Uint64()),
					CountryCode:                 "",
					RecordedBy:                  validFPLatest.Producer,
					RecordedAt:                  validFPLatest.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.vcRepo.EXPECT().UploadAttestation(ctxType, matchVINSubject(expectedVINSubject)).Return(nil)
			},
		},
		{
			name:    "failed to decode VIN from fingerprint message",
			tokenID: 129,
			setupMocks: func(mocks Mocks) {
				pairedAddr := randAddress()
				tokenID := new(big.Int).SetInt64(129)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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
				tokenID := big.NewInt(130)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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
				tokenID := big.NewInt(131)
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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

				// Create a matcher to verify the expected VIN subject
				expectedVINSubject := models.VINSubject{
					VehicleDID:                  vehicleInfo.DID.String(),
					VehicleIdentificationNumber: validFP.VIN,
					VehicleTokenID:              uint32(tokenID.Uint64()),
					CountryCode:                 "",
					RecordedBy:                  validFP.Producer,
					RecordedAt:                  validFP.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.vcRepo.EXPECT().UploadAttestation(ctxType, matchVINSubject(expectedVINSubject)).Return(errors.New("store error"))
			},
			expectedErrror: true,
		},
		{
			name:    "VC is expired",
			tokenID: 133,
			setupMocks: func(mocks Mocks) {
				tokenID := big.NewInt(133)
				pairedAddr := randAddress()
				pariedDevice := models.PairedDevice{
					Address: pairedAddr.String(),
					Type:    models.DeviceTypeAftermarket,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID10,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
				vehicleInfo := &models.VehicleInfo{
					PairedDevices: []models.PairedDevice{pariedDevice},
					NameSlug:      defaultNameSlug,
					DID: cloudevent.ERC721DID{
						ChainID:         polygonChainID,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress(defaultNFTAddress),
					},
				}
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

				// Create a matcher to verify the expected VIN subject
				expectedVINSubject := models.VINSubject{
					VehicleDID:                  vehicleInfo.DID.String(),
					VehicleIdentificationNumber: validFP.VIN,
					VehicleTokenID:              uint32(tokenID.Uint64()),
					CountryCode:                 "",
					RecordedBy:                  validFP.Producer,
					RecordedAt:                  validFP.Time,
					VehicleContractAddress:      "eth:" + defaultNFTAddress,
				}
				mocks.vcRepo.EXPECT().UploadAttestation(ctxType, matchVINSubject(expectedVINSubject)).Return(nil)
			},
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			// Initialize mocks for this specific test case
			mocks := Mocks{
				vcRepo:          NewMockVCRepo(ctrl),
				identityAPI:     NewMockIdentityAPI(ctrl),
				fingerprintRepo: NewMockFingerprintRepo(ctrl),
				vinAPI:          NewMockVINAPI(ctrl),
			}

			// Set up the mocks as defined in the test case
			tt.setupMocks(mocks)

			pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// Create a new VCController instance for this test
			vcController := vinvc.NewService(&logger,
				mocks.vcRepo, mocks.identityAPI,
				mocks.fingerprintRepo, mocks.vinAPI,
				defaultNFTAddress, polygonChainID, pk,
			)

			_, err = vcController.CreateAndStoreVINAttestation(context.Background(), tt.tokenID)
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

// matchVINSubject creates a gomock matcher that verifies the VIN subject content
type vinSubjectMatcher struct {
	expected models.VINSubject
}

func (m *vinSubjectMatcher) Matches(x interface{}) bool {
	rawEvent, ok := x.(*cloudevent.RawEvent)
	if !ok {
		return false
	}

	var credential models.Credential
	if err := json.Unmarshal(rawEvent.Data, &credential); err != nil {
		return false
	}

	var actual models.VINSubject
	if err := json.Unmarshal(credential.CredentialSubject, &actual); err != nil {
		return false
	}

	return actual.VehicleDID == m.expected.VehicleDID &&
		actual.VehicleIdentificationNumber == m.expected.VehicleIdentificationNumber &&
		actual.VehicleTokenID == m.expected.VehicleTokenID &&
		actual.RecordedBy == m.expected.RecordedBy &&
		actual.VehicleContractAddress == m.expected.VehicleContractAddress
}

func (m *vinSubjectMatcher) String() string {
	return fmt.Sprintf("VIN subject with VehicleDID: %s, VIN: %s, TokenID: %d",
		m.expected.VehicleDID, m.expected.VehicleIdentificationNumber, m.expected.VehicleTokenID)
}

func matchVINSubject(expected models.VINSubject) gomock.Matcher {
	return &vinSubjectMatcher{expected: expected}
}
