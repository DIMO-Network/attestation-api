package fingerprint

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/stretchr/testify/require"
)

func TestDecodeFingerprintMessage(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedData models.DecodedFingerprintData
		expectError  bool
	}{
		{
			name: "Valid VIN in Data",
			data: []byte(`{
				"id":"2jhCq04sdOL4fzgXccW8cJSG3vn",
				"source":"0x5e31bBc786D7bEd95216383787deA1ab0f1c1897",
				"specversion":"1.0",
				"subject":"0x24A8a66388e549BB6E5C743A6C033D611f017b2D",
				"time":"2024-05-30T15:04:05Z",
				"type":"zone.dimo.aftermarket.device.fingerprint",
				"dataschema":"dimo.zone.status/v2.0",
				"data":{
					"timestamp":1721830108107,
					"device":{"rpiUptimeSecs":109,"batteryVoltage":14.3},
					"vin":"1HGCM82633A123456",
					"protocol":"6",
					"softwareVersion":"1.25.5"
				},
				"signature":"0x8f4a67281978a93fafc9231e10c6a3489b5c732239ffc72b02e3603608c7375516f876e9ac33aa3b5a2b475521dbca4e1e68d85a797ea7b07f7d9b6369b805751c"
				}`),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					ID:          "2jhCq04sdOL4fzgXccW8cJSG3vn",
					Subject:     "0x24A8a66388e549BB6E5C743A6C033D611f017b2D",
					Type:        "zone.dimo.aftermarket.device.fingerprint",
					DataSchema:  "dimo.zone.status/v2.0",
					Time:        time.Date(2024, 5, 30, 15, 4, 5, 0, time.UTC),
					Source:      "0x5e31bBc786D7bEd95216383787deA1ab0f1c1897",
					Extras: map[string]any{
						"signature": "0x8f4a67281978a93fafc9231e10c6a3489b5c732239ffc72b02e3603608c7375516f876e9ac33aa3b5a2b475521dbca4e1e68d85a797ea7b07f7d9b6369b805751c",
					},
				},
				VIN: "1HGCM82633A123456",
			},
			expectError: false,
		},
		{
			name: "Valid VIN in Data64",
			data: []byte(fmt.Sprintf(`{"time":"2024-05-30T15:04:05Z","data_base64":"%s","source":"macaron/fingerprint"}`, mockMacronFingerprint("ABCD1234567890XYZ"))),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					Time:        time.Date(2024, 5, 30, 15, 4, 5, 0, time.UTC),
					Source:      "macaron/fingerprint",
					Extras: map[string]any{
						"data_base64": mockMacronFingerprint("ABCD1234567890XYZ"),
					},
				},
				VIN: "ABCD1234567890XYZ",
			},
			expectError: false,
		},
		{
			name: "Valid VIN from Ruptela",
			data: []byte(ruptelaStatusPayload),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					Subject:     "did:nft:1:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF_33",
					Time:        time.Date(2024, 9, 27, 8, 33, 26, 0, time.UTC),
					Source:      "0xF26421509Efe92861a587482100c6d728aBf1CD0",
					Extras: map[string]interface{}{
						"ds": "r/v0/s",
					},
				},
				VIN: "ABCD1234567890XYZ",
			},
		},
		{
			name: "Valid VIN from Tesla",
			data: []byte(teslaStatusPayload),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					Subject:     "did:nft:80003:0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8_15",
					ID:          "2pcYwspbaBFJ7NPGZ2kivkuJ12a",
					Producer:    "did:nft:80003:0x78513c8CB4D6B6079f813850376bc9c7fc8aE67f_12",
					Source:      sources.TeslaSource.String(),
					Type:        cloudevent.TypeFingerprint,
				},
				VIN: "VF33E1EB4K55F700D",
			},
		},
		{
			name: "Valid VIN from Compass",
			data: []byte(compassStatusPayload),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					Subject:     "did:nft:80003:0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8_15",
					ID:          "2pcYwspbaBFJ7NPGZ2kivkuJ12a",
					Producer:    "did:nft:80003:0x78513c8CB4D6B6079f813850376bc9c7fc8aE67f_12",
					Source:      sources.CompassSource.String(),
					Type:        cloudevent.TypeFingerprint,
				},
				VIN: "1C4SJSBP8RS133747",
			},
		},
		{
			name: "Valid VIN from Motorq",
			data: []byte(motorqStatusPayload),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					Subject:     "did:nft:1:0x0051C7656EC7ab88B098DeFB751b7401B5F6d897_123456",
					ID:          "2wSNJB8rE71kJUD7HthDgPJIEIB",
					Producer:    "did:nft:1:0x71C7656EC7ab88b098defB751B7401B5f6d8976F_789012",
					Source:      sources.MotorqSource.String(),
					Type:        cloudevent.TypeFingerprint,
					DataVersion: "v2",
				},
				VIN: "1C4SJSBP8RS133747",
			},
		},
		{
			name: "Valid VIN from Hashdog",
			data: []byte(hashdogFPPayload),
			expectedData: models.DecodedFingerprintData{
				CloudEventHeader: cloudevent.CloudEventHeader{
					SpecVersion: "1.0",
					Subject:     "did:nft:137:0xAb12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St_12345",
					ID:          "9xYzA8bCdEf2GhIj3KlMnOpQ7rS",
					Producer:    "did:nft:137:0x8a92B34cDeFg1H2i3J4k5L6m7N8o9P0qRsTuV_45678",
					Source:      sources.HashDogSource.String(),
					Type:        cloudevent.TypeFingerprint,
				},
				VIN: "1ABCD2EFGH3JKLMNO",
			},
		},
		{
			name:        "Missing VIN in Data and Data64",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z","data":{"vin":""},"data64":""}`),
			expectError: true,
		},
		{
			name:        "Invalid VIN in Data64",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z","data_base64":"AQIDBAUGBwgJCgsMDQ4PEBESFA=="}`),
			expectError: true,
		},
		{
			name:        "Invalid base64 in Data64",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z","data_base64":"!!!"}`),
			expectError: true,
		},
		{
			name:        "Invalid data length in Data64",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z","data_base64":"AQIDBA=="}`),
			expectError: true,
		},
		{
			name:        "Empty Data and Data64",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z"}`),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := Service{}
			event := cloudevent.CloudEvent[json.RawMessage]{}
			err := json.Unmarshal(tt.data, &event)
			require.NoError(t, err)
			decodedData, err := srv.decodeFingerprintMessage(event)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, decodedData)
			require.Equal(t, tt.expectedData, *decodedData)
		})
	}
}

// Mock base64 decoding and macron fingerprint for testing
func mockMacronFingerprint(vin string) string {
	vinBytes := []byte(vin)
	if len(vinBytes) > 17 {
		vinBytes = vinBytes[:17]
	}

	// we don't really care about this data, just the length
	data := macronFingerPrint{
		Header:    1,
		Timestamp: 1718967850,
		Latitude:  40.65445,
		Longitude: -73.94604,
		Protocol:  6,
	}

	copy(data.VIN[:], vinBytes)

	// Encode into base64
	buf := make([]byte, 31)
	buf[0] = data.Header
	binary.LittleEndian.PutUint32(buf[1:5], data.Timestamp)
	binary.LittleEndian.PutUint32(buf[5:9], math.Float32bits(data.Latitude))
	binary.LittleEndian.PutUint32(buf[9:13], math.Float32bits(data.Longitude))
	buf[13] = data.Protocol
	copy(buf[14:], data.VIN[:])

	return base64.StdEncoding.EncodeToString(buf)
}

var ruptelaStatusPayload = `
{
	"source": "0xF26421509Efe92861a587482100c6d728aBf1CD0",
	"data": {
		"pos": {
			"alt": 1048,
			"dir": 19730,
			"hdop": 6,
			"lat": 822721466,
			"lon": 4014316,
			"sat": 20,
			"spd": 0
		},
		"prt": 0,
		"signals": {
			"102": "0",
			"103": "0",
			"104": "4142434431323334",
			"105": "3536373839305859",
			"106": "5a00000000000000",
			"107": "0",
			"108": "0",
			"114": "0"
		},
		"trigger": 7
	},
	"ds": "r/v0/s",
	"subject": "did:nft:1:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF_33",
	"time": "2024-09-27T08:33:26Z"
}`

var teslaStatusPayload = `{
	"id": "2pcYwspbaBFJ7NPGZ2kivkuJ12a",
	"source": "0xc4035Fecb1cc906130423EF05f9C20977F643722",
	"producer": "did:nft:80003:0x78513c8CB4D6B6079f813850376bc9c7fc8aE67f_12",
	"specversion": "1.0",
	"subject": "did:nft:80003:0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8_15",
	"type": "dimo.fingerprint",
	"data": {
		"id": 234234,
		"user_id": 32425456,
		"vehicle_id": 33,
		"vin": "VF33E1EB4K55F700D",
		"color": null,
		"access_type": "OWNER",
		"granular_access": {
			"hide_private": false
		}
	}
}`

var compassStatusPayload = `{
  "id": "2pcYwspbaBFJ7NPGZ2kivkuJ12a",
  "source": "0x55BF1c27d468314Ea119CF74979E2b59F962295c",
  "producer": "did:nft:80003:0x78513c8CB4D6B6079f813850376bc9c7fc8aE67f_12",
  "specversion": "1.0",
  "subject": "did:nft:80003:0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8_15",
  "type": "dimo.fingerprint",
  "data": {
    "id": "S76960rsT8SYlrvlTfMWoQ==",
    "vehicle_id": "1C4SJSBP8RS133747",
    "timestamp": {
      "seconds": 1737988799
    },
    "transport_type": 0,
    "vehicle_type": 0,
    "position": {
      "latlng": {
        "lat": 34.821937,
        "lng": -82.291492
      }
    },
    "ingested_at": {
      "seconds": 1737988847,
      "nanos": 326690000
    }
  }
}`

var motorqStatusPayload = `{
   "id":"2wSNJB8rE71kJUD7HthDgPJIEIB",
   "source":"0x5879B43D88Fa93CE8072d6612cBc8dE93E98CE5d",
   "producer":"did:nft:1:0x71C7656EC7ab88b098defB751B7401B5f6d8976F_789012",
   "specversion":"1.0",
   "subject":"did:nft:1:0x0051C7656EC7ab88B098DeFB751b7401B5F6d897_123456",
   "type":"dimo.fingerprint",
   "dataversion":"v2",
   "data":{
	"vin": "1C4SJSBP8RS133747",      
	"signals":[
         {
            "timestamp":"2025-04-21T11:58:00.619Z",
            "name":"speed",
            "value":0
         },
         {
            "timestamp":"2025-04-21T11:58:00.619Z",
            "name":"powertrainTransmissionTravelledDistance",
            "value":43567.59749760001
         },
         {
            "timestamp":"2025-04-21T11:58:00.619Z",
            "name":"currentLocationLongitude",
            "value":-79.43646179999999
         },
         {
            "timestamp":"2025-04-21T11:58:00.619Z",
            "name":"currentLocationLatitude",
            "value":36.5810399
         }
      ]
   }
}`

var hashdogFPPayload = `{
  "id": "9xYzA8bCdEf2GhIj3KlMnOpQ7rS",
  "source": "0x4c674ddE8189aEF6e3b58F5a36d7438b2b1f6Bc2",
  "producer": "did:nft:137:0x8a92B34cDeFg1H2i3J4k5L6m7N8o9P0qRsTuV_45678",
  "specversion": "1.0",
  "subject": "did:nft:137:0xAb12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St_12345",
  "type": "dimo.fingerprint",
  "data": {
    "decodedPayload": {
      "data_base64": "Abc123XyZaBcDeF0987654321HiJkLmNoPqRsTuVwXyZ",
      "header": 1,
      "latitude": 12.345678,
      "longitude": -98.765432,
      "nsat": 1,
      "protocol": 6,
      "signature": "0x9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s0t9u8v7w6x5y4z3a2b1c0d9e8f7g6h5i4j3k2l1m",
      "timestamp": "2025-03-05T12:46:32.000Z",
      "vin": "1ABCD2EFGH3JKLMNO"
    },
    "device": {
      "id": "A1B2C3D4E5F6G7H8",
      "name": "0x1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s",
      "protocol": "lora_helium",
      "tags": {
        "env": "prod",
        "label": "prod"
      }
    },
    "header": 1,
    "id": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
    "metadata": {
      "devAddr": "123456ab",
      "fPort": "2",
      "fcnt": "2627"
    },
    "payload": "Abc123XyZaBcDeF0987654321HiJkLmNoPqRsTuVwXyZ9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s0t9u8v7w6x5y4z3a2b1c0d9e8f7g6h5i4j3k2l1m",
    "timestamp": 1741178792000,
    "vehicle": {
      "signals": [
        {
          "name": "data_base64",
          "timestamp": 1741178792000,
          "value": "Abc123XyZaBcDeF0987654321HiJkLmNoPqRsTuVwXyZ"
        },
        {
          "name": "latitude",
          "timestamp": 1741178792000,
          "value": 12.345678
        },
        {
          "name": "longitude",
          "timestamp": 1741178792000,
          "value": -98.765432
        },
        {
          "name": "nsat",
          "timestamp": 1741178792000,
          "value": 1
        },
        {
          "name": "protocol",
          "timestamp": 1741178792000,
          "value": 6
        },
        {
          "name": "signature",
          "timestamp": 1741178792000,
          "value": "0x9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s0t9u8v7w6x5y4z3a2b1c0d9e8f7g6h5i4j3k2l1m"
        },
        {
          "name": "vin",
          "timestamp": 1741178792000,
          "value": "1ABCD2EFGH3JKLMNO"
        }
      ]
    },
    "via": [
      {
        "id": "1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0T1u2V3w4X5y6Z",
        "location": {
          "latitude": 12.345678,
          "longitude": -98.765432,
          "ref": "1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0T1u2V3w4X5y6Z",
          "rssi": -110,
          "snr": 5.2
        },
        "metadata": {
          "gatewayId": "1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0T1u2V3w4X5y6Z",
          "gatewayName": "random-scrambled-identifier"
        },
        "network": "helium_iot",
        "protocol": "LORAWAN",
        "timestamp": 1741178794588,
        "txInfo": {
          "frequency": 905100000,
          "modulation": {
            "lora": {
              "bandwidth": 125000,
              "codeRate": "CR_4_5",
              "spreadingFactor": 7
            }
          }
        }
      }
    ]
  }
}`
