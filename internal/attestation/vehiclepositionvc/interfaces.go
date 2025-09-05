package vehiclepositionvc

import (
	"context"

	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
)

// VCRepo defines the interface for managing VC storage.
type VCRepo interface {
	UploadAttestation(ctx context.Context, attestation *cloudevent.RawEvent) error
}

// IdentityAPI defines the interface for identity operations.
type IdentityAPI interface {
	GetVehicleInfo(ctx context.Context, vehicleDID cloudevent.ERC721DID) (*models.VehicleInfo, error)
}

// TelemetryAPI defines the interface for fetching telemetry data.
type TelemetryAPI interface {
	GetHistoricalDataWithAuth(ctx context.Context, options telemetryapi.TelemetryHistoricalOptions, jwtToken string) ([]telemetryapi.Signal, error)
}
