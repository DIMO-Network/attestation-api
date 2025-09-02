package telemetryapi_test

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/stretchr/testify/require"
)

func TestService_GetLatestSignals(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name             string
		tokenID          int
		mockResponseBody string
		mockStatusCode   int
		expectedRecords  int
		expectedError    bool
	}{
		{
			name:    "successful response with signals",
			tokenID: 123,
			mockResponseBody: `
			{
				"data": {
					"signalsLatest": {
						"lastSeen": "2024-01-15T10:30:00Z",
						"speed": {
							"timestamp": "2024-01-15T10:30:00Z",
							"value": 65.5
						},
						"currentLocationLatitude": {
							"timestamp": "2024-01-15T10:30:00Z",
							"value": 37.7749
						}
					}
				}
			}`,
			mockStatusCode:  http.StatusOK,
			expectedRecords: 1,
			expectedError:   false,
		},
		{
			name:    "successful response with no signals",
			tokenID: 124,
			mockResponseBody: `
			{
				"data": {
					"signalsLatest": {
						"lastSeen": "2024-01-15T10:30:00Z"
					}
				}
			}`,
			mockStatusCode:  http.StatusOK,
			expectedRecords: 1,
			expectedError:   false,
		},
		{
			name:    "GraphQL API error",
			tokenID: 125,
			mockResponseBody: `
			{
				"errors": [
					{"message": "vehicle not found"}
				]
			}`,
			mockStatusCode: http.StatusOK,
			expectedError:  true,
		},
		{
			name:             "non-200 response",
			tokenID:          126,
			mockResponseBody: "",
			mockStatusCode:   http.StatusInternalServerError,
			expectedError:    true,
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

			service, err := telemetryapi.NewService(server.URL, certPool)
			require.NoError(t, err)

			// Run the test with JWT auth (using empty token for test)
			records, err := service.GetLatestSignalsWithAuth(ctx, tt.tokenID, "test-jwt-token")
			if tt.expectedError {
				require.Error(t, err)
				require.Nil(t, records)
			} else {
				require.NoError(t, err)
				require.Len(t, records, tt.expectedRecords)
				if tt.expectedRecords > 0 && len(records) > 0 && len(records[0].Signals) > 0 {
					// Check that we have signals in the record
					require.Greater(t, len(records[0].Signals), 0)
				}
			}
		})
	}
}

func TestService_GetHistoricalData(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := io.WriteString(w, `
		{
			"data": {
				"signals": [
					{
						"timestamp": "2024-01-15T10:30:00Z",
						"speed": 65.5
					},
					{
						"timestamp": "2024-01-15T11:30:00Z",
						"speed": 70.2
					}
				]
			}
		}`)
		require.NoError(t, err)
	}))
	defer server.Close()

	certPool := x509.NewCertPool()
	certPool.AddCert(server.Certificate())

	service, err := telemetryapi.NewService(server.URL, certPool)
	require.NoError(t, err)

	options := telemetryapi.TelemetryQueryOptions{
		TokenID:   123,
		StartDate: "2024-01-15T00:00:00Z",
		EndDate:   "2024-01-15T23:59:59Z",
		Signals:   []string{"speed"},
	}

	records, err := service.GetHistoricalDataWithAuth(ctx, options, "test-jwt-token")
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Equal(t, "speed", records[0].Signals[0].Name)
	require.Equal(t, 65.5, records[0].Signals[0].Value)
	require.Equal(t, "speed", records[1].Signals[0].Name)
	require.Equal(t, 70.2, records[1].Signals[0].Value)
}
