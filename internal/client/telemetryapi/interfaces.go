package telemetryapi

import "context"

// TelemetryAPI defines the interface for telemetry operations.
type TelemetryAPI interface {
	// GetLatestSignalsWithAuth fetches the latest telemetry signals for a vehicle with JWT authentication.
	GetLatestSignalsWithAuth(ctx context.Context, tokenID int, jwtToken string) ([]TelemetryRecord, error)

	// GetHistoricalDataWithAuth fetches historical telemetry data for a vehicle with JWT authentication.
	GetHistoricalDataWithAuth(ctx context.Context, options TelemetryQueryOptions, jwtToken string) ([]TelemetryRecord, error)
}

// Ensure Service implements TelemetryAPI interface.
var _ TelemetryAPI = (*Service)(nil)
