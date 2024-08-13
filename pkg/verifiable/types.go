package verifiable

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// LocationTypeCellID represents the cell ID location type.
	LocationTypeCellID = "cellId"
	// LocationTypeLatLng represents the latitude/longitude location type.
	LocationTypeLatLng = "latitude/longitude"
	// LocationTypeGatewayID represents the gateway ID location type.
	LocationTypeGatewayID = "gatewayId"
)

// Credential represents a verifiable credential.
type Credential struct {
	Context           []any            `json:"@context,omitempty"`
	ID                string           `json:"id,omitempty"`
	Type              []string         `json:"type,omitempty"`
	Issuer            string           `json:"issuer,omitempty"`
	ValidFrom         string           `json:"validFrom,omitempty"`
	ValidTo           string           `json:"validTo,omitempty"`
	CredentialSubject json.RawMessage  `json:"credentialSubject,omitempty"`
	CredentialStatus  CredentialStatus `json:"credentialStatus,omitempty"`
	Proof             Proof            `json:"proof,omitempty"`
}

// VINSubject represents the subject of the VIN verifiable credential.
type VINSubject struct {
	ID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// VehicleIdentificationNumber is the VIN of the vehicle.
	VehicleIdentificationNumber string `json:"vehicleIdentificationNumber,omitempty"`
	// RecordedBy is the entity that recoreded the VIN.
	RecordedBy string `json:"recordedBy,omitempty"`
	// RecorededAt is the time the VIN was recoreded.
	RecordedAt time.Time `json:"recordedAt,omitempty"`
	// CountryCode that VIN belongs to.
	CountryCode string `json:"countryCode,omitempty"`
}

// BitstringStatusListSubject represents the subject of the bitstring status list verifiable credential.
type BitstringStatusListSubject struct {
	ID            string `json:"id,omitempty"`
	Type          string `json:"type,omitempty"`
	StatusPurpose string `json:"statusPurpose,omitempty"`
	EncodedList   string `json:"encodedList,omitempty"`
}

// CredentialStatus represents the status of the verifiable credential.
type CredentialStatus struct {
	ID                   string `json:"id,omitempty"`
	Type                 string `json:"type,omitempty"`
	StatusPurpose        string `json:"statusPurpose,omitempty"`
	StatusListIndex      uint   `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// ProofOptions contains the options for generating a proof.
type ProofOptions struct {
	Type               string `json:"type,omitempty"`
	Cryptosuite        string `json:"cryptosuite,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	Created            string `json:"created,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
}

// proofOptionsWithContext contains the proof options with the context.
// this is used for canonicalization.
type ProofOptionsWithContext struct {
	Context []any `json:"@context,omitempty"`
	ProofOptions
}

// Proof contains the signed proof value and options.
type Proof struct {
	ProofOptions
	ProofValue string `json:"proofValue,omitempty"`
}

type VerificationControlDocument struct {
	Context              []string   `json:"@context,omitempty"`
	ID                   string     `json:"id,omitempty"`
	VerificationMethod   []MultiKey `json:"verificationMethod,omitempty"`
	Authentication       []string   `json:"authentication,omitempty"`
	AssertionMethod      []string   `json:"assertionMethod,omitempty"`
	CapabilityDelegation []string   `json:"capabilityDelegation,omitempty"`
	CapabilityInvocation []string   `json:"capabilityInvocation,omitempty"`
}

type MultiKey struct {
	ID                 string `json:"id,omitempty"`
	Type               string `json:"type,omitempty"`
	Controller         string `json:"controller,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// POMSubject represents the subject of the Proof of Movement VC.
type POMSubject struct {
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// RecordedBy is the entity that recorded the event.
	RecordedBy string     `json:"recordedBy,omitempty"`
	Locations  []Location `json:"locations"`
}

// Location represents a single location event with type, value, and timestamp.
type Location struct {
	LocationType  string        `json:"locationType"`
	LocationValue LocationValue `json:"locationValue"`
	Timestamp     time.Time     `json:"timestamp"`
}

// LocationValue represents a generic interface for location values.
type LocationValue interface {
	isLocationValue()
}

// CellID represents a cell ID location value.
type CellID struct {
	CellID string `json:"cellId"`
}

func (CellID) isLocationValue() {}

// LatLng represents a latitude/longitude location value.
type LatLng struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

func (LatLng) isLocationValue() {}

// GatewayID represents a gateway ID location value.
type GatewayID struct {
	GatewayID string `json:"gatewayId"`
}

func (GatewayID) isLocationValue() {}

// UnmarshalJSON custom unmarshals a Location to handle the polymorphic LocationValue.
func (l *Location) UnmarshalJSON(data []byte) error {
	type Alias Location
	aux := &struct {
		LocationValue json.RawMessage `json:"locationValue"`
		*Alias
	}{
		Alias: (*Alias)(l),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch l.LocationType {
	case LocationTypeCellID:
		var cellID CellID
		if err := json.Unmarshal(aux.LocationValue, &cellID); err != nil {
			return err
		}
		l.LocationValue = cellID
	case LocationTypeLatLng:
		var latLng LatLng
		if err := json.Unmarshal(aux.LocationValue, &latLng); err != nil {
			return err
		}
		l.LocationValue = latLng
	case LocationTypeGatewayID:
		var gatewayID GatewayID
		if err := json.Unmarshal(aux.LocationValue, &gatewayID); err != nil {
			return err
		}
		l.LocationValue = gatewayID
	default:
		return fmt.Errorf("unknown location type: %s", l.LocationType)
	}

	return nil
}
