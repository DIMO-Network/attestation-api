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
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/ethereum/go-ethereum/common"
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
				"source":"0xAff1B580F05F2ee577162B39851b79f84F82f46A",
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
					Source:      "0xAff1B580F05F2ee577162B39851b79f84F82f46A",
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
					Source:      "0x3A6603E1065C9b3142403b1b7e349a6Ae936E819",
					Extras: map[string]interface{}{
						"ds": "r/v0/s",
					},
				},
				VIN: "ABCD1234567890XYZ",
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
			srv := Service{ruptelaSource: common.HexToAddress("0x3A6603E1065C9b3142403b1b7e349a6Ae936E819")}
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
	"source": "0x3A6603E1065C9b3142403b1b7e349a6Ae936E819",
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
