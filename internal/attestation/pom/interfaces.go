//go:generate mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=pom_test
package pom

import (
	"context"
	"encoding/json"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/ethereum/go-ethereum/common"
)

// VCRepo defines the interface for manging VC storage.
type VCRepo interface {
	GetLatestVINVC(ctx context.Context, tokenID uint32) (*verifiable.Credential, error)
	StoreVINVC(ctx context.Context, tokenID uint32, vinvc json.RawMessage) error
}

// IdentityAPI defines the interface for identity operations.
type IdentityAPI interface {
	GetVehicleInfo(ctx context.Context, tokenID uint32) (*models.VehicleInfo, error)
}

// ConnectivityRepo defines the interface for retrieving connectivity events.
type ConnectivityRepo interface {
	GetAutoPiEvents(ctx context.Context, pairedDeviceIMEI string, after, before time.Time, limit int) ([][]byte, error)
	GetHashDogEvents(ctx context.Context, pairedDeviceAddr common.Address, after, before time.Time, limit int) ([][]byte, error)
	GetStatusEvents(ctx context.Context, vehicleTokenID uint32, after, before time.Time, limit int) ([][]byte, error)
}

// VINAPI defines the interface for VIN validation.
type VINAPI interface {
	DecodeVIN(ctx context.Context, vin, countryCode string) (string, error)
}

// Issuer defines the interface for creating control documents.
type Issuer interface {
	CreatePOMVC(vinSubject verifiable.POMSubject, expTime time.Time) ([]byte, error)
}
