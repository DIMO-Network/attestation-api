//go:generate mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=pom_tests
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
	GetAutoPiEvents(ctx context.Context, pairedDeviceIMEI string, after time.Time, limit int) ([][]byte, error)
	GetHashDogEvents(ctx context.Context, pairedDeviceAddr common.Address, after time.Time, limit int) ([][]byte, error)
	GetStatusEvents(ctx context.Context, vehicleTokenID uint32, after time.Time, limit int) ([][]byte, error)
}

// PairedDevice represents a device paired with a token.
type PairedDevice struct {
	Address common.Address `json:"address"`
	Type    DeviceType     `json:"type"`
}

type DeviceType string

const (
	AutoPi   DeviceType = "AutoPi"
	Smartcar DeviceType = "Smartcar"
	Tesla    DeviceType = "Tesla"
	Macaron  DeviceType = "Macaron"
)

// VINAPI defines the interface for VIN validation.
type VINAPI interface {
	DecodeVIN(ctx context.Context, vin, countryCode string) (string, error)
}

// Issuer defines the interface for creating control documents.
type Issuer interface {
	CreateBitstringStatusListVC(tokenID uint32, revoked bool) ([]byte, error)
	CreateKeyControlDoc() ([]byte, error)
	CreatePOMVC(vinSubject verifiable.POMSubject, expTime time.Time) ([]byte, error)
	CreateJSONLDDoc() ([]byte, error)
	CreateVocabWebpage() ([]byte, error)
}

// AutoPiLocation represents a location for AutoPi
type AutoPiLocation struct {
	Timestamp time.Time `json:"timestamp"`
	CellID    string    `json:"cell_id"`
}

// StatusLocation represents a location for Smartcar and Tesla
type StatusLocation struct {
	Timestamp time.Time `json:"timestamp"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
}

// MacaronLocation represents a location for Macaron
type MacaronLocation struct {
	Timestamp time.Time `json:"timestamp"`
	GatewayID string    `json:"gateway_id"`
}
