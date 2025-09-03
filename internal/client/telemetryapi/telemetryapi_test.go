package telemetryapi_test

import (
	"context"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		expectedSignals  int
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
			expectedSignals: 2,
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
			expectedSignals: 0,
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
			signals, err := service.GetLatestSignalsWithAuth(ctx, tt.tokenID, "test-jwt-token")
			if tt.expectedError {
				require.Error(t, err)
				require.Nil(t, signals)
			} else {
				require.NoError(t, err)
				require.Len(t, signals, tt.expectedSignals)
				if tt.expectedSignals > 0 && len(signals) > 0 {
					// Check that we have signals with proper structure
					require.NotEmpty(t, signals[0].Name)
					require.NotNil(t, signals[0].Value)
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

	startTime, _ := time.Parse(time.RFC3339, "2024-01-15T00:00:00Z")
	endTime, _ := time.Parse(time.RFC3339, "2024-01-15T23:59:59Z")
	options := telemetryapi.TelemetryQueryOptions{
		TokenID:   big.NewInt(123),
		StartDate: startTime,
		EndDate:   endTime,
		Signals:   []string{"speed"},
	}

	signals, err := service.GetHistoricalDataWithAuth(ctx, options, "test-jwt-token")
	require.NoError(t, err)
	require.Len(t, signals, 2)
	require.Equal(t, "speed", signals[0].Name)
	require.Equal(t, 65.5, signals[0].Value)
	require.Equal(t, "speed", signals[1].Name)
	require.Equal(t, 70.2, signals[1].Value)
}
