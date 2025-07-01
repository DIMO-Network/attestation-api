package types

import (
	"encoding/json"
	"time"
)

// Credential represents a verifiable credential.
type Credential struct {
	ValidFrom         time.Time       `json:"validFrom,omitempty"`
	ValidTo           time.Time       `json:"validTo,omitempty"`
	CredentialSubject json.RawMessage `json:"credentialSubject,omitempty"`
}

// VINSubject represents the subject of the VIN verifiable credential.
type VINSubject struct {
	VehicleDID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// VehicleIdentificationNumber is the VIN of the vehicle.
	VehicleIdentificationNumber string `json:"vehicleIdentificationNumber,omitempty"`
	// RecordedBy is the entity that recorded the VIN.
	RecordedBy string `json:"recordedBy,omitempty"`
	// RecordedAt is the time the VIN was recorded.
	RecordedAt time.Time `json:"recordedAt,omitempty"`
	// CountryCode that VIN belongs to.
	CountryCode string `json:"countryCode,omitempty"`
}
