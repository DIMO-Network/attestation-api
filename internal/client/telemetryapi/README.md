# Telemetry API Client

This package provides a client for interacting with the DIMO Telemetry GraphQL API.

## Overview

The telemetry API client allows you to fetch telemetry data from vehicles in the DIMO network with JWT authentication. It supports:

- Fetching latest signals with authentication
- Retrieving historical data with authentication

## Usage

### Basic Setup

```go
package main

import (
    "context"
    "log"
    
    "github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
)

func main() {
    // Create a new telemetry service
    service, err := telemetryapi.NewService("https://telemetry-api.dimo.zone", nil)
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    tokenID := 123
    jwtToken := "your-jwt-token"
    
    // Get latest signals with authentication
    signals, err := service.GetLatestSignalsWithAuth(ctx, tokenID, jwtToken)
    if err != nil {
        log.Fatal(err)
    }
    
    for _, record := range signals {
        log.Printf("Source: %s, Timestamp: %s", record.Source, record.Timestamp)
        for _, signal := range record.Signals {
            log.Printf("  %s: %v", signal.Name, signal.Value)
        }
    }
}
```

### Getting Historical Data

```go
// Define query options
options := telemetryapi.TelemetryQueryOptions{
    TokenID:   123,
    StartDate: "2024-01-15T00:00:00Z",
    EndDate:   "2024-01-15T23:59:59Z",
    Signals:   []string{"speed", "currentLocationLatitude", "currentLocationLongitude"},
}

// Fetch historical data with authentication
records, err := service.GetHistoricalDataWithAuth(ctx, options, jwtToken)
if err != nil {
    log.Fatal(err)
}
```

### Processing Signals from Records

```go
// Process signals directly from records
for _, record := range records {
    for _, signal := range record.Signals {
        switch signal.Name {
        case "speed":
            log.Printf("Speed at %s: %v", signal.Timestamp, signal.Value)
        case "currentLocationLatitude":
            log.Printf("Latitude at %s: %v", signal.Timestamp, signal.Value)
        case "powertrainTransmissionTravelledDistance":
            log.Printf("Odometer at %s: %v km", signal.Timestamp, signal.Value)
        }
    }
}
```

## Data Structures

### TelemetryRecord

Represents a collection of signals from a source at a specific timestamp:

```go
type TelemetryRecord struct {
    Timestamp string   `json:"timestamp"`
    Source    string   `json:"source"`
    Signals   []Signal `json:"signals"`
}
```

### Signal

Represents an individual telemetry signal:

```go
type Signal struct {
    Name      string      `json:"name"`
    Value     interface{} `json:"value"`
    Timestamp string      `json:"timestamp"`
}
```



### TelemetryQueryOptions

Options for querying telemetry data:

```go
type TelemetryQueryOptions struct {
    TokenID   int      `json:"tokenId"`
    StartDate string   `json:"startDate,omitempty"`
    EndDate   string   `json:"endDate,omitempty"`
    Interval  string   `json:"interval,omitempty"`
    Signals   []string `json:"signals,omitempty"`
}
```

## Authentication

The telemetry API client supports TLS certificate pools for secure connections. Pass a certificate pool when creating the service if needed:

```go
import "crypto/x509"

certPool := x509.NewCertPool()
// Add certificates to the pool...

service, err := telemetryapi.NewService("https://telemetry-api.dimo.zone", certPool)
```

## Error Handling

The client returns errors for various scenarios:
- Network connectivity issues
- Invalid GraphQL queries
- API errors from the telemetry service
- Parsing errors

Always check for errors when making API calls:

```go
if err != nil {
    log.Printf("Telemetry API error: %v", err)
    // Handle error appropriately
}
```

## Configuration

The telemetry API URL is configured through the `TELEMETRY_URL` environment variable in the main application settings.

## Integration with Attestation Services

This client is designed to be used within attestation services to fetch telemetry data for creating verifiable credentials. The service is initialized in `internal/app/setup.go` and can be injected into attestation services as needed.

Example usage in an attestation service:

```go
func NewMyAttestationService(
    vcRepo VCRepo,
    identityAPI IdentityAPI,
    telemetryAPI telemetryapi.TelemetryAPI,
    // other dependencies...
) *MyService {
    return &MyService{
        telemetryAPI: telemetryAPI,
        // other fields...
    }
}

func (s *MyService) CreateAttestation(ctx context.Context, tokenID uint32, jwtToken string) error {
    // Fetch telemetry data with authentication
    signals, err := s.telemetryAPI.GetLatestSignalsWithAuth(ctx, int(tokenID), jwtToken)
    if err != nil {
        return fmt.Errorf("failed to fetch telemetry data: %w", err)
    }
    
    // Process signals and create attestation...
    for _, record := range signals {
        for _, signal := range record.Signals {
            switch signal.Name {
            case "speed":
                // Process speed data
            case "currentLocationLatitude":
                // Process latitude data
            case "powertrainTransmissionTravelledDistance":
                // Process odometer data
            }
        }
    }
    
    return nil
}
```
