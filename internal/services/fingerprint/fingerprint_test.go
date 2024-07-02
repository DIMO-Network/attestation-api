package fingerprint

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeFingerprintMessage(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectedVIN string
		expectError bool
	}{
		{
			name:        "Valid VIN in Data",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z","data":{"vin":"1HGCM82633A123456"}}`),
			expectedVIN: "1HGCM82633A123456",
			expectError: false,
		},
		{
			name:        "Valid VIN in Data64",
			data:        []byte(fmt.Sprintf(`{"time":"2024-05-30T15:04:05Z","data_base64":"%s"}`, mockMacronFingerprint("ABCD1234567890XYZ"))),
			expectedVIN: "ABCD1234567890XYZ",
			expectError: false,
		},

		{
			name:        "Invalid JSON",
			data:        []byte(`{"time":"2024-05-30T15:04:05Z","data":{"vin":"1HGCM82633A123456"`),
			expectError: true,
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
			decodedData, err := decodeFingerprintMessage(tt.data)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, decodedData)
			require.Equal(t, tt.expectedVIN, decodedData.VIN)
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
