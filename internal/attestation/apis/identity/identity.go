// Package identity provides functionality to interact with the identity GraphQL API.
package identity

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

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
)

// Service interacts with the identity GraphQL API.
type Service struct {
	httpClient  *http.Client
	apiQueryURL string
}

// NewService creates a new instance of Service with optional TLS certificate pool.
func NewService(apiBaseURL string, certPool *x509.CertPool) (*Service, error) {
	// Configure HTTP client with optional TLS certificate pool.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    certPool,
			},
		},
	}
	path, err := url.JoinPath(apiBaseURL, "query")
	if err != nil {
		return nil, fmt.Errorf("create idenitiy URL: %w", err)
	}

	return &Service{
		apiQueryURL: path,
		httpClient:  httpClient,
	}, nil
}

// GetVehicleInfo fetches vehicle information from the identity API.
func (s *Service) GetVehicleInfo(ctx context.Context, tokenID uint32) (*models.VehicleInfo, error) {
	requestBody := map[string]any{
		"query": query,
		"variables": map[string]any{
			"tokenId": tokenID,
		},
	}

	reqBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiQueryURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send GraphQL request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // ignore error

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 response from GraphQL API: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GraphQL response body: %w", err)
	}

	var respBody graphQLResponse
	if err := json.Unmarshal(bodyBytes, &respBody); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL response: %w", err)
	}

	if len(respBody.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL API error: %s", respBody.Errors[0].Message)
	}

	var pairedDevices []models.PairedDevice
	if respBody.Data.Vehicle.AftermarketDevice != nil {
		pairedDevices = append(pairedDevices, models.PairedDevice{
			Address:          common.HexToAddress(respBody.Data.Vehicle.AftermarketDevice.Address),
			Type:             models.DeviceTypeAftermarket,
			ManufacturerName: respBody.Data.Vehicle.AftermarketDevice.Manufacturer.Name,
			IMEI:             respBody.Data.Vehicle.AftermarketDevice.IMEI,
		})
	}
	if respBody.Data.Vehicle.SyntheticDevice != nil {
		pairedDevices = append(pairedDevices, models.PairedDevice{
			Address: common.HexToAddress(respBody.Data.Vehicle.SyntheticDevice.Address),
			Type:    models.DeviceTypeSynthetic,
		})
	}
	if respBody.Data.Vehicle.Definition == nil || respBody.Data.Vehicle.Definition.ID.value == nil {
		return nil, fmt.Errorf("vehicle is missing definition ID")
	}
	vehicleInfo := &models.VehicleInfo{
		TokenID:       tokenID,
		PairedDevices: pairedDevices,
		NameSlug:      *respBody.Data.Vehicle.Definition.ID.value,
	}
	return vehicleInfo, nil
}
