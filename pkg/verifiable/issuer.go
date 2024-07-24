// Package verifiable provides functionality managing verifiable credentials.
package verifiable

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
)

var (
	secp256k1Prefix = []byte{0xe7, 0x01}
	trueList        = MustEncodeList([]byte{1})
	falseList       = MustEncodeList([]byte{0})

	//go:embed w3.org_ns_credentials_v2.json
	w3cNSCredentialsV2 []byte
	//go:embed schema_vin.json
	vinSchema []byte
)

// Config contains the configuration for a Issuer.
type Config struct {
	PrivateKey        []byte
	ChainID           *big.Int
	VehicleNFTAddress common.Address
	BaseStatusURL     string
	BaseKeyURL        string
}

// Issuer issues various Verifiable Credentials.
type Issuer struct {
	privateKey         *ecdsa.PrivateKey
	encodedPublicKey   string
	chainID            *big.Int
	vehicleNFTAddress  common.Address
	issuer             string
	verificationMethod string
	ldProcessor        *ld.JsonLdProcessor
	ldOptions          *ld.JsonLdOptions
	baseStatusURL      url.URL
}

// NewIssuer creates a new instance of Issuer.
func NewIssuer(config Config) (*Issuer, error) {
	privateKey, err := crypto.ToECDSA(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}
	pubKeyEnc := "z" + base58.Encode(append(secp256k1Prefix, crypto.CompressPubkey(&privateKey.PublicKey)...))

	ldProc := ld.NewJsonLdProcessor()
	options, err := DefaultLdOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON-LD options: %w", err)
	}

	baseStatusURL, err := url.Parse(config.BaseStatusURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base status URL: %w", err)
	}

	baseKeyURL, err := url.Parse(config.BaseKeyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base key URL: %w", err)
	}

	issuer := baseKeyURL.String()
	verfifcationMethod := issuer + "#key1"

	return &Issuer{
		privateKey:         privateKey,
		encodedPublicKey:   pubKeyEnc,
		chainID:            config.ChainID,
		vehicleNFTAddress:  config.VehicleNFTAddress,
		issuer:             issuer,
		verificationMethod: verfifcationMethod,
		ldProcessor:        ldProc,
		ldOptions:          options,
		baseStatusURL:      *baseStatusURL,
	}, nil
}

// CreateVINVC creates a verifiable credential for a vehicle identification number and token ID.
func (i *Issuer) CreateVINVC(subject VINSubject, expirationDate time.Time) ([]byte, error) {
	id := uuid.New().String()
	issuanceDate := time.Now().UTC().Format(time.RFC3339)

	tokenIDStr := strconv.FormatUint(uint64(subject.VehicleTokenId), 10)
	statusURL := i.baseStatusURL.JoinPath(tokenIDStr)
	credential := Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://schema.org",
		},
		ID:        "urn:uuid:" + id,
		Type:      []string{"VerifiableCredential", "Vehicle"},
		Issuer:    i.issuer,
		ValidFrom: issuanceDate,
		ValidTo:   expirationDate.Format(time.RFC3339),
		CredentialStatus: CredentialStatus{
			ID:                   statusURL.String(),
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      0,
			StatusListCredential: i.baseStatusURL.String(),
		},
	}
	subject.ID = fmt.Sprintf("did:nft:%d_erc721:%s_%d", i.chainID, i.vehicleNFTAddress, subject.VehicleTokenId)

	rawSubject, err := json.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential subject: %w", err)
	}
	credential.CredentialSubject = rawSubject

	proofOptions := ProofOptions{
		Type:               dataIntegrityProof,
		VerificationMethod: i.verificationMethod,
		Cryptosuite:        ecdsaRdfc2019,
		Created:            issuanceDate,
		ProofPurpose:       "assertionMethod",
	}

	proof, err := CreateProof(credential, proofOptions, i.privateKey, i.ldProcessor, i.ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}
	credential.Proof = proof

	signedCreds, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed credential: %w", err)
	}

	return signedCreds, nil
}

func (i *Issuer) CreateBitstringStatusListVC(tokenID uint32, revoked bool) ([]byte, error) {
	tokenIDStr := strconv.FormatUint(uint64(tokenID), 10)
	statusURL := i.baseStatusURL.JoinPath(tokenIDStr)
	issuanceDate := time.Now().UTC().Format(time.RFC3339)

	credential := Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:        statusURL.String(),
		Type:      []string{"VerifiableCredential", "BitstringStatusListCredential"},
		Issuer:    i.issuer,
		ValidFrom: issuanceDate,
	}

	encodedList := trueList
	if revoked {
		encodedList = falseList
	}
	subject := BitstringStatusListSubject{
		ID:            statusURL.String() + "#list",
		Type:          "BitstringStatusList",
		StatusPurpose: "revocation",
		EncodedList:   encodedList,
	}
	rawSubject, err := json.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential subject: %w", err)
	}
	credential.CredentialSubject = rawSubject

	proofOptions := ProofOptions{
		Type:               dataIntegrityProof,
		VerificationMethod: i.verificationMethod,
		Cryptosuite:        ecdsaRdfc2019,
		Created:            issuanceDate,
		ProofPurpose:       "assertionMethod",
	}
	proof, err := CreateProof(credential, proofOptions, i.privateKey, i.ldProcessor, i.ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}
	credential.Proof = proof

	signedCreds, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed credential: %w", err)
	}

	return signedCreds, nil
}

// EncodeList compresses and base64 encodes a list of bytes.
func EncodeList(data []byte) (string, error) {
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	_, err := gzipWriter.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to gzip writer: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to close gzip writer: %w", err)
	}
	// base64 encode the gzip compressed data
	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

// MustEncodeList compresses and base64 encodes a list of bytes.
func MustEncodeList(data []byte) string {
	encodedData, err := EncodeList(data)
	if err != nil {
		panic(fmt.Errorf("failed to gzip encode data: %w", err))
	}
	return encodedData
}

// CreateKeyControlDoc creates a key control document for the issuer.
// This document is used to get the public key of the issuer.
func (i *Issuer) CreateKeyControlDoc() ([]byte, error) {
	controlDoc := VerificationControlDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/multikey/v1",
		},
		ID: i.issuer,
		VerificationMethod: []MultiKey{
			{
				ID:                 i.verificationMethod,
				Type:               "Multikey",
				Controller:         i.issuer,
				PublicKeyMultibase: i.encodedPublicKey,
			},
		},
		AssertionMethod: []string{
			i.verificationMethod,
		},
	}

	jsonDoc, err := json.Marshal(controlDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to marsal controll doc: %w", err)
	}

	return jsonDoc, nil
}
