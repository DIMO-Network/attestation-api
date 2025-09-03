// Package telemetryapi provides functionality to interact with the telemetry GraphQL API.
package telemetryapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/DIMO-Network/model-garage/pkg/vss"
)

// Service interacts with the telemetry GraphQL API.
type Service struct {
	httpClient  *http.Client
	apiQueryURL string
}

// NewService creates a new instance of Service with optional TLS certificate pool.
func NewService(apiBaseURL string, certPool *x509.CertPool) (*Service, error) {
	// Configure HTTP client with optional TLS certificate pool.
	httpClient := &http.Client{
		Timeout: 30 * time.Second, // Longer timeout for telemetry queries
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    certPool,
			},
		},
	}
	path, err := url.JoinPath(apiBaseURL, "query")
	if err != nil {
		return nil, fmt.Errorf("create telemetry URL: %w", err)
	}
	return &Service{
		apiQueryURL: path,
		httpClient:  httpClient,
	}, nil
}

// GetLatestSignalsWithAuth fetches the latest telemetry signals for a vehicle with JWT authentication.
func (s *Service) GetLatestSignalsWithAuth(ctx context.Context, tokenID int, jwtToken string) ([]Signal, error) {
	requestBody := map[string]any{
		"query": latestSignalsQuery,
		"variables": map[string]any{
			"tokenId": tokenID,
		},
	}

	var response graphQLResponse
	if err := s.executeQueryWithAuth(ctx, requestBody, &response, jwtToken); err != nil {
		return nil, err
	}

	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL API error: %s", response.Errors[0].Message)
	}

	if response.Data.SignalsLatest == nil {
		return []Signal{}, nil
	}

	// Convert SignalCollection to TelemetryRecord format
	return s.convertSignalCollectionToRecords(*response.Data.SignalsLatest), nil
}

// GetHistoricalDataWithAuth fetches historical telemetry data for a vehicle with JWT authentication.
func (s *Service) GetHistoricalDataWithAuth(ctx context.Context, options TelemetryQueryOptions, jwtToken string) ([]Signal, error) {
	requestBody := map[string]any{
		"query": historicalQuery,
		"variables": map[string]any{
			"tokenId": options.TokenID,
			"from":    options.StartDate,
			"to":      options.EndDate,
		},
	}

	var response graphQLResponse
	if err := s.executeQueryWithAuth(ctx, requestBody, &response, jwtToken); err != nil {
		return nil, err
	}

	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL API error: %s", response.Errors[0].Message)
	}

	// Convert SignalAggregations to TelemetryRecord format
	return s.convertSignalAggregationsToRecords(response.Data.Signals), nil
}

// executeQueryWithAuth executes a GraphQL query with JWT authentication and unmarshals the response.
func (s *Service) executeQueryWithAuth(ctx context.Context, requestBody map[string]any, response interface{}, jwtToken string) error {
	reqBytes, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiQueryURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return fmt.Errorf("failed to create GraphQL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send GraphQL request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // ignore error

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-200 response from GraphQL API: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read GraphQL response body: %w", err)
	}

	if err := json.Unmarshal(bodyBytes, response); err != nil {
		return fmt.Errorf("failed to unmarshal GraphQL response: %w", err)
	}

	return nil
}

// convertSignalCollectionToRecords converts SignalCollection to TelemetryRecord format.
func (s *Service) convertSignalCollectionToRecords(collection SignalCollection) []Signal {
	var signals []Signal

	// Convert each signal field to Signal format
	if collection.CurrentLocationLatitude != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldCurrentLocationLatitude,
			Value:     collection.CurrentLocationLatitude.Value,
			Timestamp: collection.CurrentLocationLatitude.Timestamp,
		})
	}
	if collection.CurrentLocationLongitude != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldCurrentLocationLongitude,
			Value:     collection.CurrentLocationLongitude.Value,
			Timestamp: collection.CurrentLocationLongitude.Timestamp,
		})
	}
	if collection.CurrentLocationApproximateLatitude != nil {
		signals = append(signals, Signal{
			Name:      "currentLocationApproximateLatitude",
			Value:     collection.CurrentLocationApproximateLatitude.Value,
			Timestamp: collection.CurrentLocationApproximateLatitude.Timestamp,
		})
	}
	if collection.CurrentLocationApproximateLongitude != nil {
		signals = append(signals, Signal{
			Name:      "currentLocationApproximateLongitude",
			Value:     collection.CurrentLocationApproximateLongitude.Value,
			Timestamp: collection.CurrentLocationApproximateLongitude.Timestamp,
		})
	}
	if collection.PowertrainTransmissionTravelledDistance != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldPowertrainTransmissionTravelledDistance,
			Value:     collection.PowertrainTransmissionTravelledDistance.Value,
			Timestamp: collection.PowertrainTransmissionTravelledDistance.Timestamp,
		})
	}
	if collection.Speed != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldSpeed,
			Value:     collection.Speed.Value,
			Timestamp: collection.Speed.Timestamp,
		})
	}
	if collection.ObdDTCList != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldOBDDTCList,
			Value:     collection.ObdDTCList.Value,
			Timestamp: collection.ObdDTCList.Timestamp,
		})
	}
	if collection.ObdStatusDTCCount != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldOBDStatusDTCCount,
			Value:     collection.ObdStatusDTCCount.Value,
			Timestamp: collection.ObdStatusDTCCount.Timestamp,
		})
	}
	if collection.ChassisAxleRow1WheelLeftTirePressure != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldChassisAxleRow1WheelLeftTirePressure,
			Value:     collection.ChassisAxleRow1WheelLeftTirePressure.Value,
			Timestamp: collection.ChassisAxleRow1WheelLeftTirePressure.Timestamp,
		})
	}
	if collection.ChassisAxleRow1WheelRightTirePressure != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldChassisAxleRow1WheelRightTirePressure,
			Value:     collection.ChassisAxleRow1WheelRightTirePressure.Value,
			Timestamp: collection.ChassisAxleRow1WheelRightTirePressure.Timestamp,
		})
	}
	if collection.ChassisAxleRow2WheelLeftTirePressure != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldChassisAxleRow2WheelLeftTirePressure,
			Value:     collection.ChassisAxleRow2WheelLeftTirePressure.Value,
			Timestamp: collection.ChassisAxleRow2WheelLeftTirePressure.Timestamp,
		})
	}
	if collection.ChassisAxleRow2WheelRightTirePressure != nil {
		signals = append(signals, Signal{
			Name:      vss.FieldChassisAxleRow2WheelRightTirePressure,
			Value:     collection.ChassisAxleRow2WheelRightTirePressure.Value,
			Timestamp: collection.ChassisAxleRow2WheelRightTirePressure.Timestamp,
		})
	}

	return signals
}

// convertSignalAggregationsToRecords converts SignalAggregations to TelemetryRecord format.
func (s *Service) convertSignalAggregationsToRecords(aggregations []SignalAggregations) []Signal {
	var signals []Signal

	for _, agg := range aggregations {
		// Convert each aggregation field to Signal format
		if agg.CurrentLocationLatitude != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldCurrentLocationLatitude,
				Value:     *agg.CurrentLocationLatitude,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.CurrentLocationLongitude != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldCurrentLocationLongitude,
				Value:     *agg.CurrentLocationLongitude,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.CurrentLocationApproximateLatitude != nil {
			signals = append(signals, Signal{
				Name:      "currentLocationApproximateLatitude",
				Value:     *agg.CurrentLocationApproximateLatitude,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.CurrentLocationApproximateLongitude != nil {
			signals = append(signals, Signal{
				Name:      "currentLocationApproximateLongitude",
				Value:     *agg.CurrentLocationApproximateLongitude,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.PowertrainTransmissionTravelledDistance != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldPowertrainTransmissionTravelledDistance,
				Value:     *agg.PowertrainTransmissionTravelledDistance,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.Speed != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldSpeed,
				Value:     *agg.Speed,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.ObdDTCList != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldOBDDTCList,
				Value:     *agg.ObdDTCList,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.ObdStatusDTCCount != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldOBDStatusDTCCount,
				Value:     *agg.ObdStatusDTCCount,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.ChassisAxleRow1WheelLeftTirePressure != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldChassisAxleRow1WheelLeftTirePressure,
				Value:     *agg.ChassisAxleRow1WheelLeftTirePressure,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.ChassisAxleRow1WheelRightTirePressure != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldChassisAxleRow1WheelRightTirePressure,
				Value:     *agg.ChassisAxleRow1WheelRightTirePressure,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.ChassisAxleRow2WheelLeftTirePressure != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldChassisAxleRow2WheelLeftTirePressure,
				Value:     *agg.ChassisAxleRow2WheelLeftTirePressure,
				Timestamp: agg.Timestamp,
			})
		}
		if agg.ChassisAxleRow2WheelRightTirePressure != nil {
			signals = append(signals, Signal{
				Name:      vss.FieldChassisAxleRow2WheelRightTirePressure,
				Value:     *agg.ChassisAxleRow2WheelRightTirePressure,
				Timestamp: agg.Timestamp,
			})
		}
	}

	return signals
}
