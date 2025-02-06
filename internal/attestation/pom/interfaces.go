//go:generate mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=pom_test
package pom

import (
	"context"
	"encoding/json"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
)

// VCRepo defines the interface for manging VC storage.
type VCRepo interface {
	StorePOMVC(ctx context.Context, vehicleDID, producerDID string, vinvc json.RawMessage) error
}

// IdentityAPI defines the interface for identity operations.
type IdentityAPI interface {
	GetVehicleInfo(ctx context.Context, vehicleDID cloudevent.NFTDID) (*models.VehicleInfo, error)
}

// ConnectivityRepo defines the interface for retrieving connectivity events.
type ConnectivityRepo interface {
	GetAutoPiEvents(ctx context.Context, pairedDevice *models.PairedDevice, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error)
	GetHashDogEvents(ctx context.Context, pairedDevice *models.PairedDevice, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error)
	GetSyntheticstatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error)
	GetRuptelaStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error)
}

// Issuer defines the interface for creating control documents.
type Issuer interface {
	CreatePOMVC(vinSubject verifiable.POMSubject) ([]byte, error)
}
