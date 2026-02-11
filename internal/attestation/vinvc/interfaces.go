package vinvc

import (
	"context"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
)

// VCRepo defines the interface for manging VC storage.
type VCRepo interface {
	UploadAttestation(ctx context.Context, attestation *cloudevent.RawEvent) error
}

// IdentityAPI defines the interface for identity operations.
type IdentityAPI interface {
	GetVehicleInfo(ctx context.Context, vehicleDID cloudevent.ERC721DID) (*models.VehicleInfo, error)
}

// FingerprintRepo defines the interface for fingerprint message operations.
type FingerprintRepo interface {
	GetLatestFingerprintMessages(ctx context.Context, vehicle cloudevent.ERC721DID, pairedDeviceAddr models.PairedDevice) (*models.DecodedFingerprintData, error)
}
