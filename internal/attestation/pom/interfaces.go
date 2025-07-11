//go:generate go tool mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=pom_test
package pom

import (
	"context"
	"encoding/json"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
)

// VCRepo defines the interface for manging VC storage.
type VCRepo interface {
	StorePOMVC(ctx context.Context, vehicleDID, producerDID string, vinvc json.RawMessage) error
}

// IdentityAPI defines the interface for identity operations.
type IdentityAPI interface {
	GetVehicleInfo(ctx context.Context, vehicleDID cloudevent.ERC721DID) (*models.VehicleInfo, error)
}

// Issuer defines the interface for creating control documents.
type Issuer interface {
	CreatePOMVC(vinSubject types.POMSubject) ([]byte, error)
}
