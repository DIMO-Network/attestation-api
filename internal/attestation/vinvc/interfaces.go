//go:generate mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=vinvc_test
package vinvc

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

// FingerprintRepo defines the interface for fingerprint message operations.
type FingerprintRepo interface {
	GetLatestFingerprintMessages(ctx context.Context, pairedDeviceAddr common.Address) (*models.DecodedFingerprintData, error)
}

// VINAPI defines the interface for VIN validation.
type VINAPI interface {
	DecodeVIN(ctx context.Context, vin, countryCode string) (string, error)
}

// Issuer defines the interface for creating control documents.
type Issuer interface {
	CreateBitstringStatusListVC(tokenID uint32, revoked bool) ([]byte, error)
	CreateKeyControlDoc() ([]byte, error)
	CreateVINVC(vinSubject verifiable.VINSubject, expTime time.Time) ([]byte, error)
}