package verfiable

import (
	"encoding/json"
)

// Credential represents a verifiable credential.
type Credential struct {
	Context           []string         `json:"@context,omitempty"`
	ID                string           `json:"id,omitempty"`
	Type              []string         `json:"type,omitempty"`
	Issuer            string           `json:"issuer,omitempty"`
	IssuanceDate      string           `json:"issuanceDate,omitempty"`
	ExpirationDate    string           `json:"expirationDate,omitempty"`
	CredentialSubject json.RawMessage  `json:"credentialSubject,omitempty"`
	CredentialStatus  CredentialStatus `json:"credentialStatus,omitempty"`
	Proof             Proof            `json:"proof,omitempty"`
}

// CredentialSubject is an interface for the subject of the verifiable credential.
type CredentialSubject interface {
	isCredentialSubject() string
}

// VINSubject represents the subject of the VIN verifiable credential.
type VINSubject struct {
	ID                          string `json:"id,omitempty"`
	VehicleIdentificationNumber string `json:"vehicleIdentificationNumber,omitempty"`
}

func (VINSubject) isCredentialSubject() string { return "VINSubject" }

// CredentialStatus represents the status of the verifiable credential.
type CredentialStatus struct {
	ID                   string `json:"id,omitempty"`
	Type                 string `json:"type,omitempty"`
	StatusPurpose        string `json:"statusPurpose,omitempty"`
	StatusListIndex      string `json:"statusListIndex,omitempty"`
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
	Context []string `json:"@context,omitempty"`
	ProofOptions
}

// Proof contains the signed proof value and options.
type Proof struct {
	ProofOptions
	ProofValue string `json:"proofValue,omitempty"`
}
