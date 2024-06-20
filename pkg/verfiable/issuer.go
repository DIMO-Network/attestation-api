package verfiable

import (
	"crypto/ecdsa"
	_ "embed" //nolint
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

var secp256k1Prefix = []byte{0xe7, 0x01}

//go:embed w3.org_ns_credentials_v2.json
var w3cNSCredentialsV2 []byte

//go:embed schema_vin.json
var vinSchema []byte

type Config struct {
	PrivateKey        []byte
	ChainID           *big.Int
	VehicleNFTAddress common.Address
	BaseStatusURL     string
}

type Issuer struct {
	privateKey         *ecdsa.PrivateKey
	chainID            *big.Int
	vehicleNFTAddress  common.Address
	issuerDID          string
	verificationMethod string
	ldProcessor        *ld.JsonLdProcessor
	ldOptions          *ld.JsonLdOptions
	baseStatusURL      *url.URL
}

func NewIssuer(config Config) (*Issuer, error) {
	privateKey, err := crypto.ToECDSA(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}

	keyEnc := "z" + base58.Encode(append(secp256k1Prefix, crypto.CompressPubkey(&privateKey.PublicKey)...))
	issuer := "did:key:" + keyEnc
	verificationMethod := issuer + "#" + keyEnc

	ldProc := ld.NewJsonLdProcessor()
	options, err := DefaultLdOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON-LD options: %w", err)
	}

	baseURL, err := url.Parse(config.BaseStatusURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base status URL: %w", err)
	}

	return &Issuer{
		privateKey:         privateKey,
		chainID:            config.ChainID,
		vehicleNFTAddress:  config.VehicleNFTAddress,
		issuerDID:          issuer,
		verificationMethod: verificationMethod,
		ldProcessor:        ldProc,
		ldOptions:          options,
		baseStatusURL:      baseURL,
	}, nil
}

// DID returns the issuer's DID.
func (i *Issuer) DID() string {
	return i.issuerDID
}

// CreateVINVC creates a verifiable credential for a vehicle identification number and token ID.
func (i *Issuer) CreateVINVC(vin string, tokenID uint32, expirationDate time.Time) ([]byte, error) {
	id := uuid.New().String()
	issuanceDate := time.Now().UTC().Format(time.RFC3339)

	tokenIDStr := strconv.FormatUint(uint64(tokenID), 10)
	statusURL := i.baseStatusURL.JoinPath(tokenIDStr)
	credential := Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://schema.org",
		},
		ID:             "urn:uuid:" + id,
		Type:           []string{"VerifiableCredential", "Vehicle"},
		Issuer:         i.issuerDID,
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate.Format(time.RFC3339),
		CredentialStatus: CredentialStatus{
			ID:                   statusURL.String(),
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      strconv.FormatUint(uint64(tokenID), 10),
			StatusListCredential: i.baseStatusURL.String(),
		},
	}
	subject := VINSubject{
		ID:                          fmt.Sprintf("did:nft:%d_erc721:%s_%d", i.chainID, i.vehicleNFTAddress, tokenID),
		VehicleIdentificationNumber: vin,
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
