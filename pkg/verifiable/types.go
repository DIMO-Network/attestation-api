package verifiable

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
	ValidFrom         string           `json:"validFrom,omitempty"`
	ExpirationDate    string           `json:"expirationDate,omitempty"`
	CredentialSubject json.RawMessage  `json:"credentialSubject,omitempty"`
	CredentialStatus  CredentialStatus `json:"credentialStatus,omitempty"`
	Proof             Proof            `json:"proof,omitempty"`
}

// VINSubject represents the subject of the VIN verifiable credential.
type VINSubject struct {
	ID                          string `json:"id,omitempty"`
	VehicleIdentificationNumber string `json:"vehicleIdentificationNumber,omitempty"`
	CountryCode                 string `json:"countryCode,omitempty"`
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
	Context []string `json:"@context,omitempty"`
	ProofOptions
}

// Proof contains the signed proof value and options.
type Proof struct {
	ProofOptions
	ProofValue string `json:"proofValue,omitempty"`
}

//	{
//		"@context": [
//		  "https://www.w3.org/ns/did/v1",
//		  "https://w3id.org/security/multikey/v1"
//		],
//		"id": "did:example:123",
//		"verificationMethod": [{
//		  "id": "https://example.com/issuer/123#key-1",
//		  "type": "Multikey",
//		  "controller": "https://example.com/issuer/123",
//		  "publicKeyMultibase": "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
//		}, {
//		  "id": "https://example.com/issuer/123#key-2",
//		  "type": "Multikey",
//		  "controller": "https://example.com/issuer/123",
//		  "publicKeyMultibase": "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJ
//			Uz2sG9FE42shbn2xkZJh54"
//		}],
//		"authentication": [
//		  "did:example:123#key-1"
//		],
//		"assertionMethod": [
//		  "did:example:123#key-2"
//		],
//		"capabilityDelegation": [
//		  "did:example:123#key-2"
//		],
//		"capabilityInvocation": [
//		  "did:example:123#key-2"
//		]
//	  }
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
