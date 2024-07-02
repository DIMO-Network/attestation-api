package identity_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/attestation-api/internal/services/identity"
	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

const testSlug = "toyota_tacoma-4wd_2023"

func TestService_GetPairedDevices(t *testing.T) {
	deviceAddr1 := randAddress()
	deviceAddr2 := randAddress()
	ctx := context.Background()
	tests := []struct {
		name             string
		vehicleTokenID   uint32
		mockResponseBody string
		mockStatusCode   int
		expectedInfo     *models.VehicleInfo
		expectedError    bool
	}{
		{
			name:           "successful response with devices",
			vehicleTokenID: 123,
			mockResponseBody: fmt.Sprintf(`
			{
				"data": {
					"vehicle": {
						"definition": {
							"id": "toyota_tacoma-4wd_2023"
						},
						"aftermarketDevice": {
							"Address": "%s"
						},
						"syntheticDevice": {
							"Address": "%s"
						}
					}
				}
			}`, deviceAddr1, deviceAddr2),
			mockStatusCode: http.StatusOK,
			expectedInfo: &models.VehicleInfo{
				TokenID:  123,
				NameSlug: testSlug,
				PairedDevices: []models.PairedDevice{
					{Address: deviceAddr1, Type: models.DeviceTypeAftermarket},
					{Address: deviceAddr2, Type: models.DeviceTypeSynthetic},
				},
			},
			expectedError: false,
		},
		{
			name:           "successful response with no devices",
			vehicleTokenID: 125,
			mockResponseBody: `
			{
				"data": {
					"vehicle": {
						"definition": {
							"id": "toyota_tacoma-4wd_2023"
						}
					}
				}
			}`,
			mockStatusCode: http.StatusOK,
			expectedInfo: &models.VehicleInfo{
				TokenID:  125,
				NameSlug: testSlug,
			},
			expectedError: false,
		},
		{
			name:           "GraphQL API error",
			vehicleTokenID: 126,
			mockResponseBody: `
			{
				"errors": [
					{"message": "some error"}
				]
			}`,
			mockStatusCode: http.StatusOK,
			expectedInfo:   nil,
			expectedError:  true,
		},
		{
			name:             "non-200 response",
			vehicleTokenID:   127,
			mockResponseBody: "",
			mockStatusCode:   http.StatusInternalServerError,
			expectedInfo:     nil,
			expectedError:    true,
		},
		{
			name:           "successful response with only aftermarket device",
			vehicleTokenID: 128,
			mockResponseBody: fmt.Sprintf(`
			{
				"data": {
					"vehicle": {
						"definition": {
							"id": "toyota_tacoma-4wd_2023"
						},
						"aftermarketDevice": {
							"Address": "%s"
						}
					}
				}
			}`, deviceAddr1),
			mockStatusCode: http.StatusOK,
			expectedInfo: &models.VehicleInfo{
				TokenID:  128,
				NameSlug: testSlug,
				PairedDevices: []models.PairedDevice{
					{Address: deviceAddr1, Type: models.DeviceTypeAftermarket},
				},
			},
			expectedError: false,
		},
		{
			name:           "successful response with only synthetic device",
			vehicleTokenID: 129,
			mockResponseBody: fmt.Sprintf(`
			{
				"data": {
					"vehicle": {
						"definition": {
							"id": "toyota_tacoma-4wd_2023"
						},
						"syntheticDevice": {
							"Address": "%s"
						}
					}
				}
			}`, deviceAddr2),
			mockStatusCode: http.StatusOK,
			expectedInfo: &models.VehicleInfo{
				TokenID:  129,
				NameSlug: testSlug,
				PairedDevices: []models.PairedDevice{
					{Address: deviceAddr2, Type: models.DeviceTypeSynthetic},
				},
			},
			expectedError: false,
		},
		{
			name:           "successful response with no definition ID",
			vehicleTokenID: 130,
			mockResponseBody: fmt.Sprintf(`
			{
				"data": {
					"vehicle": {
						"definition": {
							"id": null
						},
						"syntheticDevice": {
							"Address": "%s"
						}
					}
				}
			}`, deviceAddr2),
			mockStatusCode: http.StatusOK,
			expectedInfo:   nil,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Set up mock server with TLS.
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponseBody != "" {
					_, err := io.WriteString(w, tt.mockResponseBody)
					require.NoError(t, err)
				}
			}))
			defer server.Close()

			// Create a cert pool for the test server.
			certPool := x509.NewCertPool()
			certPool.AddCert(server.Certificate())

			service, err := identity.NewService(server.URL, certPool)
			require.NoError(t, err)

			// Run the test.
			devices, err := service.GetVehicleInfo(ctx, tt.vehicleTokenID)
			if tt.expectedError {
				require.Error(t, err)
				require.Nil(t, devices)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedInfo, devices)
			}
		})
	}
}

func randAddress() common.Address {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		panic(fmt.Sprintf("failed to generate private key: %v", err))
	}
	return crypto.PubkeyToAddress(privateKey.PublicKey)
}
