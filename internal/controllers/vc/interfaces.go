//go:generate mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=vc_test
package vc

import (
	"context"

	"github.com/DIMO-Network/attestation-api/pkg/models"
)

// VCService defines the interface for VC operations.
type VCService interface {
	GenerateAndStoreVC(ctx context.Context, vcUUID string, tokenID uint32, aftermarketTokenID, syntheticTokenID *uint32, vin string) error
}

// IdentityService defines the interface for identity operations.
type IdentityService interface {
	GetPairedDevices(ctx context.Context, tokenID uint32) ([]models.PairedDevice, error)
}

// FingerprintService defines the interface for fingerprint message operations.
type FingerprintService interface {
	GetLatestFingerprintMessages(ctx context.Context, tokenID uint32) ([]models.FingerprintMessage, error)
}

// VINService defines the interface for VIN validation.
type VINService interface {
	ValidateVIN(ctx context.Context, vin string) error
}
