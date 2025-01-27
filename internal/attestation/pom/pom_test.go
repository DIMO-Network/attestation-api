package pom_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/pom"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/lorawan"
	"github.com/DIMO-Network/model-garage/pkg/twilio"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_CreatePOMVC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdentityAPI := NewMockIdentityAPI(ctrl)
	mockConnectivityRepo := NewMockConnectivityRepo(ctrl)
	mockVCRepo := NewMockVCRepo(ctrl)
	mockIssuer := NewMockIssuer(ctrl)

	logger := zerolog.New(nil)
	service, err := pom.NewService(&logger, mockIdentityAPI, mockConnectivityRepo, mockVCRepo, mockIssuer, "0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF", 137)
	require.NoError(t, err)

	ctx := context.TODO()
	tokenID := uint32(1234)
	inputStatusv1 := cloudevent.CloudEvent[json.RawMessage]{}
	err = json.Unmarshal([]byte(inputStatusv1Bytes), &inputStatusv1)
	require.NoError(t, err)
	inputStatusv2 := cloudevent.CloudEvent[json.RawMessage]{}
	err = json.Unmarshal([]byte(inputStatusv2Bytes), &inputStatusv2)
	require.NoError(t, err)
	inputRuptela := cloudevent.CloudEvent[json.RawMessage]{}
	err = json.Unmarshal([]byte(inputRuptelaBytes), &inputRuptela)
	require.NoError(t, err)

	tests := []struct {
		name              string
		mockSetup         func()
		expectError       bool
		expectedVCStored  bool
		expectedVCContent []byte
	}{
		{
			name: "Success with AutoPi device",
			mockSetup: func() {
				pairedDevice := models.PairedDevice{
					Type:             models.DeviceTypeAftermarket,
					ManufacturerName: "AutoPi",
					IMEI:             "123456789012345",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						pairedDevice,
					},
				}
				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				events := []twilio.ConnectionEvent{
					{
						Location:  &twilio.LocationInfo{CellID: "12345"},
						Timestamp: time.Now(),
					},
					{
						Location:  &twilio.LocationInfo{CellID: "67890"},
						Timestamp: time.Now().Add(-5 * time.Minute),
					},
				}
				eventBytes := make([]cloudevent.CloudEvent[json.RawMessage], len(events))
				for i, event := range events {
					cloudEvent := cloudevent.CloudEvent[twilio.ConnectionEvent]{
						Data: event,
						CloudEventHeader: cloudevent.CloudEventHeader{
							Time: event.Timestamp,
						},
					}
					b, _ := json.Marshal(cloudEvent.Data)
					eventBytes[i] = cloudevent.CloudEvent[json.RawMessage]{Data: b}
				}

				mockConnectivityRepo.EXPECT().GetAutoPiEvents(ctx, &pairedDevice, gomock.Any(), gomock.Any(), gomock.Any()).Return(eventBytes, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, pairedDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(nil)
			},
			expectError:       false,
			expectedVCStored:  true,
			expectedVCContent: []byte(`{"vc": "some-vc"}`),
		},
		{
			name: "Success with Status device",
			mockSetup: func() {
				pairedDevice := models.PairedDevice{
					Type:    models.DeviceTypeSynthetic,
					Address: "0xf5c0337B31464D4f2232FEb2E71b4c7A175e7c52",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						pairedDevice,
					},
				}
				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				eventBytes := []cloudevent.CloudEvent[json.RawMessage]{
					inputStatusv1,
					inputStatusv2,
				}

				mockConnectivityRepo.EXPECT().GetSyntheticstatusEvents(ctx, vehicleInfo.DID, gomock.Any(), gomock.Any(), gomock.Any()).Return(eventBytes, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, pairedDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(nil)
			},
			expectError:       false,
			expectedVCStored:  true,
			expectedVCContent: []byte(`{"vc": "some-vc"}`),
		},
		{
			name: "Success with Macaron device",
			mockSetup: func() {
				pairedDevice := models.PairedDevice{
					Type:             models.DeviceTypeAftermarket,
					ManufacturerName: "HashDog",
					Address:          "0xf5c0337B31464D4f2232FEb2E71b4c7A175e7c52",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						pairedDevice,
					},
				}

				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				events := []lorawan.Data{
					{
						Via: []lorawan.Via{
							{
								Metadata: lorawan.GWMetadata{GatewayID: "gateway123"},
							},
						},
						Timestamp: time.Now().UnixMilli(),
					},
					{
						Via: []lorawan.Via{
							{
								Metadata: lorawan.GWMetadata{GatewayID: "gateway456"},
							},
						},
						Timestamp: time.Now().Add(-5 * time.Minute).UnixMilli(),
					},
				}

				eventBytes := make([]cloudevent.CloudEvent[json.RawMessage], len(events))
				for i, event := range events {
					cloudEvent := cloudevent.CloudEvent[json.RawMessage]{
						CloudEventHeader: cloudevent.CloudEventHeader{
							Time: time.UnixMilli(event.Timestamp),
							ID:   fmt.Sprintf("event-%d", i),
						},
					}
					b, _ := json.Marshal(event)
					cloudEvent.Data = b
					eventBytes[i] = cloudEvent
				}

				mockConnectivityRepo.EXPECT().GetHashDogEvents(ctx, &pairedDevice, gomock.Any(), gomock.Any(), gomock.Any()).Return(eventBytes, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, pairedDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(nil)
			},
			expectError:       false,
			expectedVCStored:  true,
			expectedVCContent: []byte(`{"vc": "some-vc"}`),
		},
		{
			name: "Success with Ruptela device",
			mockSetup: func() {
				pairedDevice := models.PairedDevice{
					Type:             models.DeviceTypeAftermarket,
					ManufacturerName: "Ruptela",
					Address:          "0xf5c0337B31464D4f2232FEb2E71b4c7A175e7c52",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						pairedDevice,
					},
				}

				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				events := []cloudevent.CloudEvent[json.RawMessage]{
					inputRuptela,
				}

				mockConnectivityRepo.EXPECT().GetRuptelaStatusEvents(ctx, vehicleInfo.DID, gomock.Any(), gomock.Any(), gomock.Any()).Return(events, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, pairedDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(nil)
			},
			expectError: false,
		},
		{
			name: "Multiple devices AutoPi priority",
			mockSetup: func() {
				autoPiDevice := models.PairedDevice{
					Type:             models.DeviceTypeAftermarket,
					ManufacturerName: "AutoPi",
					IMEI:             "123456789012345",
				}
				statusDevice := models.PairedDevice{
					Type:    models.DeviceTypeSynthetic,
					Address: "0xf5c0337B31464D4f2232FEb2E71b4c7A175e7c52",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						statusDevice,
						autoPiDevice,
					},
				}
				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				events := []twilio.ConnectionEvent{
					{
						Location:  &twilio.LocationInfo{CellID: "12345"},
						Timestamp: time.Now(),
					},
					{
						Location:  &twilio.LocationInfo{CellID: "67890"},
						Timestamp: time.Now().Add(-5 * time.Minute),
					},
				}
				eventBytes := make([]cloudevent.CloudEvent[json.RawMessage], len(events))
				for i, event := range events {
					cloudEvent := cloudevent.CloudEvent[twilio.ConnectionEvent]{
						Data: event,
						CloudEventHeader: cloudevent.CloudEventHeader{
							Time: event.Timestamp,
						},
					}
					b, _ := json.Marshal(cloudEvent.Data)
					eventBytes[i] = cloudevent.CloudEvent[json.RawMessage]{Data: b}
				}

				mockConnectivityRepo.EXPECT().GetAutoPiEvents(ctx, &autoPiDevice, gomock.Any(), gomock.Any(), gomock.Any()).Return(eventBytes, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, autoPiDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(nil)
			},
			expectError:       false,
			expectedVCStored:  true,
			expectedVCContent: []byte(`{"vc": "some-vc"}`),
		},
		{
			name: "Multiple devices Status fallback",
			mockSetup: func() {
				autoPiDevice := models.PairedDevice{
					Type:             models.DeviceTypeAftermarket,
					ManufacturerName: "AutoPi",
					IMEI:             "123456789012345",
				}
				statusDevice := models.PairedDevice{
					Type:    models.DeviceTypeSynthetic,
					Address: "0xf5c0337B31464D4f2232FEb2E71b4c7A175e7c52",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						statusDevice,
						autoPiDevice,
					},
				}
				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				eventBytes := []cloudevent.CloudEvent[json.RawMessage]{
					inputStatusv1,
					inputStatusv2,
				}

				mockConnectivityRepo.EXPECT().GetAutoPiEvents(ctx, &autoPiDevice, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
				mockConnectivityRepo.EXPECT().GetSyntheticstatusEvents(ctx, vehicleInfo.DID, gomock.Any(), gomock.Any(), gomock.Any()).Return(eventBytes, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, statusDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(nil)
			},
			expectError:       false,
			expectedVCStored:  true,
			expectedVCContent: []byte(`{"vc": "some-vc"}`),
		},
		{
			name: "Error getting vehicle info",
			mockSetup: func() {
				vehicleInfo := cloudevent.NFTDID{
					ChainID:         137,
					TokenID:         tokenID,
					ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
				}
				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo).Return(nil, fmt.Errorf("vehicle info error"))
			},
			expectError:      true,
			expectedVCStored: false,
		},
		{
			name: "Error storing POM VC",
			mockSetup: func() {
				pairedDevice := models.PairedDevice{
					Type:    models.DeviceTypeSynthetic,
					Address: "0xf5c0337B31464D4f2232FEb2E71b4c7A175e7c52",
				}
				vehicleInfo := &models.VehicleInfo{
					DID: cloudevent.NFTDID{
						ChainID:         137,
						TokenID:         tokenID,
						ContractAddress: common.HexToAddress("0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"),
					},
					PairedDevices: []models.PairedDevice{
						pairedDevice,
					},
				}
				mockIdentityAPI.EXPECT().GetVehicleInfo(ctx, vehicleInfo.DID).Return(vehicleInfo, nil)

				eventBytes := []cloudevent.CloudEvent[json.RawMessage]{
					inputStatusv1,
					inputStatusv2,
				}

				mockConnectivityRepo.EXPECT().GetSyntheticstatusEvents(ctx, vehicleInfo.DID, gomock.Any(), gomock.Any(), gomock.Any()).Return(eventBytes, nil)
				mockIssuer.EXPECT().CreatePOMVC(gomock.Any()).Return([]byte(`{"vc": "some-vc"}`), nil)
				mockVCRepo.EXPECT().StorePOMVC(ctx, vehicleInfo.DID, pairedDevice.DID, json.RawMessage(`{"vc": "some-vc"}`)).Return(fmt.Errorf("store error"))
			},
			expectError:      true,
			expectedVCStored: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockSetup != nil {
				tt.mockSetup()
			}
			err := service.CreatePOMVC(ctx, tokenID)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

var (
	inputStatusv1Bytes = `{
		"id": "randomIDnumber",
		"specversion": "1.0",
		"source": "dimo/integration/22N2xaPOq2WW2gAHBHd0Ikn4Zob",
		"subject": "Vehicle123",
		"time": "2022-01-01T12:34:56Z",
		"type": "DIMO",
        "vehicleTokenId": 123,
		"data": {
			"latitude": 37.7749,
			"longitude": -122.4194
		}
	}`
	inputStatusv2Bytes = `{
    "id": "2fHbFXPWzrVActDb7WqWCfqeiYe",
    "source": "dimo/integration/22N2xaPOq2WW2gAHBHd0Ikn4Zob",
    "specversion": "1.0",
    "dataschema": "testschema/v2.0",
    "subject": "0x98D78d711C0ec544F6fb5d54fcf6559CF41546a9",
    "time": "2024-04-18T17:20:46.436008782Z",
    "type": "com.dimo.device.status",
    "vehicleTokenId": 123,
    "data": {
        "timestamp": 1713460846435,
        "device": {
            "rpiUptimeSecs": 218,
            "batteryVoltage": 12.28
        },
        "vehicle": {
            "signals": [
                {
                    "timestamp": 1713460846435,
                    "name": "longitude",
                    "value": -56.50151833333334
                },
                {
                    "timestamp": 1713460846435,
                    "name": "latitude",
                    "value": 56.27014
                },
                {
                    "timestamp": 1713460847435,
                    "name": "longitude",
                    "value": -56.5017
                },
                {
                    "timestamp": 1713460847435,
                    "name": "latitude",
                    "value": 56.271
                }
            ]
        }
    }
}`
	inputRuptelaBytes = `
	{
    "id": "2ntM3FpVxTqkjJNeixHzyOyB3mz",
    "source": "0x4Dc84a226102c08e911A5159e165e616e3A877A8",
    "producer": "did:nft:137:0x325b45949C833986bC98e98a49F3CA5C5c4643B5_14",
    "specversion": "1.0",
    "subject": "did:nft:137:0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8_431",
    "time": "2024-10-24T16:35:14Z",
    "type": "dimo.status",
    "datacontenttype": "application/json",
    "dataversion": "r/v0/loc",
    "data": {
        "location": [
            {
                "ts": 1729787700,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787701,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787702,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787703,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787704,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787705,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787706,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787707,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787708,
                "lat": 452700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787709,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787710,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787711,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787712,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787713,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            },
            {
                "ts": 1729787714,
                "lat": 422700833,
                "lon": -715014150,
                "alt": 896,
                "dir": 0,
                "hdop": 0
            }
        ]
    },
    "signature": "0xbb0cca928355df6454db8244846d9b58fcec0ba465651d609e7dc9564b94461a10f7c0fe82060eaeb4d7e8f01a1edea8fe8635310860ea1be1abbc14a1f944e81c"
}`
)
