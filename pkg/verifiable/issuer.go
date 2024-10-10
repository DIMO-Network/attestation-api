// Package verifiable provides functionality managing verifiable credentials.
package verifiable

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/verifiable/vocab"
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
)

// Config contains the configuration for a Issuer.
type Config struct {
	PrivateKey        []byte
	ChainID           *big.Int
	VehicleNFTAddress common.Address
	BaseStatusURL     *url.URL
	BaseKeyURL        *url.URL
	BaseVocabURL      *url.URL
	BaseJSONLDURL     *url.URL
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
	vocabulary         *vocab.Vocabulary
	localContext       string
}

// NewIssuer creates a new instance of Issuer.
func NewIssuer(config Config) (*Issuer, error) {
	privateKey, err := crypto.ToECDSA(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}
	pubKeyEnc := "z" + base58.Encode(append(secp256k1Prefix, crypto.CompressPubkey(&privateKey.PublicKey)...))

	ldProc := ld.NewJsonLdProcessor()

	if config.BaseStatusURL == nil {
		return nil, fmt.Errorf("base status URL is required")
	}
	if config.BaseKeyURL == nil {
		return nil, fmt.Errorf("base key URL is required")
	}
	if config.BaseVocabURL == nil {
		return nil, fmt.Errorf("base vocab URL is required")
	}
	if config.BaseJSONLDURL == nil {
		return nil, fmt.Errorf("base JSON-LD URL is required")
	}
	vocabulary := createVocab(config.BaseVocabURL)
	localSchemaContext := config.BaseJSONLDURL.String()

	contextDoc, err := vocabulary.RenderJSONLD()
	if err != nil {
		return nil, fmt.Errorf("failed to render JSON-LD document: %w", err)
	}

	options, err := DefaultLdOptions(localSchemaContext, string(contextDoc))
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON-LD options: %w", err)
	}

	issuer := config.BaseKeyURL.String()
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
		baseStatusURL:      *config.BaseStatusURL,
		vocabulary:         vocabulary,
		localContext:       localSchemaContext,
	}, nil
}

// CreateVINVC creates a verifiable credential for a vehicle identification number and token ID.
func (i *Issuer) CreateVINVC(subject VINSubject, expirationDate time.Time) ([]byte, error) {
	id := uuid.New().String()
	issuanceDate := time.Now().UTC().Format(time.RFC3339)

	tokenIDStr := strconv.FormatUint(uint64(subject.VehicleTokenID), 10)
	statusURL := i.baseStatusURL.JoinPath(tokenIDStr)
	credential := Credential{
		Context: []any{
			"https://www.w3.org/ns/credentials/v2",
			map[string]string{"vehicleIdentificationNumber": "https://schema.org/vehicleIdentificationNumber"},
			i.localContext,
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
	subject.ID = fmt.Sprintf("did:nft:%d_erc721:%s_%d", i.chainID, i.vehicleNFTAddress, subject.VehicleTokenID)

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

func (i *Issuer) CreatePOMVC(subject POMSubject) ([]byte, error) {
	id := uuid.New().String()
	issuanceDate := time.Now().UTC().Format(time.RFC3339)

	tokenIDStr := strconv.FormatUint(uint64(subject.VehicleTokenID), 10)
	statusURL := i.baseStatusURL.JoinPath(tokenIDStr)
	credential := Credential{
		Context: []any{
			"https://www.w3.org/ns/credentials/v2",
			i.localContext,
		},
		ID:        "urn:uuid:" + id,
		Type:      []string{"VerifiableCredential", "Vehicle"},
		Issuer:    i.issuer,
		ValidFrom: issuanceDate,
		CredentialStatus: CredentialStatus{
			ID:                   statusURL.String(),
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      0,
			StatusListCredential: i.baseStatusURL.String(),
		},
	}
	subject.ID = fmt.Sprintf("did:nft:%d_erc721:%s_%d", i.chainID, i.vehicleNFTAddress, subject.VehicleTokenID)

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
		Context: []any{
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

// CreateJSONLDDoc creates a JSON-LD document for all VC types.
func (i *Issuer) CreateJSONLDDoc() ([]byte, error) {
	doc, err := i.vocabulary.RenderJSONLD()
	if err != nil {
		return nil, fmt.Errorf("failed to render JSON-LD document: %w", err)
	}
	return doc, nil
}

// CreateVocabWebpage creates a webpage for the vocabulary.
func (i *Issuer) CreateVocabWebpage() ([]byte, error) {
	page, err := i.vocabulary.RenderWebpage()
	if err != nil {
		return nil, fmt.Errorf("failed to render webpage: %w", err)
	}
	return page, nil
}

func createVocab(baseURL *url.URL) *vocab.Vocabulary {
	terms := []vocab.Term{
		{
			Name:        "recordedAt",
			Description: "The date and time the event was recorded. Format should be in RFC3339.",
			Usage:       "Use this term to record the date and time the information was recorded.",
		},
		{
			Name:        "recordedBy",
			Description: "The entity that recorded the event. This can be an Ethereum address or an entity name. If an Ethereum address, it should be prefixed with 'eth:', and if an entity name, it should be prefixed with 'ent:'.",
			Usage:       "Use this term to record the entity that recorded the event.",
		},
		{
			Name:        "vehicleTokenId",
			Description: "The token ID of the vehicle NFT.",
			Usage:       "Use this term to record the token ID of the vehicle NFT.",
		},
		{
			Name:        "vehicleContractAddress",
			Description: "The address of the vehicle NFT contract. Format should be in hexadecimal Ethereum address.",
			Usage:       "Use this term to record the address of the vehicle NFT contract.",
		},
		{
			Name:        "locations",
			Description: "The recorded locations of the vehicle.",
			Usage:       "Use this term to record the physical locations of the vehicle.",
		},
		{
			Name:        "locationType",
			Description: fmt.Sprintf("The type of location value. Must be one of: '%s', '%s', '%s'", LocationTypeCellID, LocationTypeGatewayID, LocationTypeH3Cell),
			Usage:       "Use this term to record the type of location value.",
		},
		{
			Name:        "locationValue",
			Description: "The value of the location. This can be a cell ID, latitude/longitude, or gateway ID.",
			Usage:       "Use this term to record the value of the location.",
		},
		{
			Name:        "cellId",
			Description: "The cell ID of cellular tower that the vehicle connected to.",
			Usage:       "Use this term to record the cell ID of the cellular tower.",
		},
		{
			Name:        "h3CellId",
			Description: "The H3 cell ID of the vehicle's location.",
			Usage:       "Use this term to record the H3 cell ID of the vehicle's location.",
		},
		{
			Name:        "gatewayId",
			Description: "The ID of the gateway that the vehicle connected to.",
			Usage:       "Use this term to record the ID of the gateway.",
		},
	}

	return vocab.NewVocabulary(terms, *baseURL)
}
