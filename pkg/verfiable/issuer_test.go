package verfiable_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/verfiable"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestCreateVINVC(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	tests := []struct {
		name           string
		config         verfiable.Config
		vin            string
		tokenID        uint32
		expirationDate time.Time
		expectError    bool
	}{
		{
			name: "Valid Config 1",
			config: verfiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			vin:            "1HGCM82633A123456",
			tokenID:        1,
			expirationDate: time.Now().Add(24 * time.Hour),
			expectError:    false,
		},
		{
			name: "Valid Config 2",
			config: verfiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(2),
				VehicleNFTAddress: common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdef"),
				BaseStatusURL:     "https://status.example.org",
			},
			vin:            "1HGCM82633B654321",
			tokenID:        2,
			expirationDate: time.Now().Add(24 * time.Hour),
			expectError:    false,
		},
		{
			name: "Expired Date",
			config: verfiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			vin:            "1HGCM82633A123456",
			tokenID:        1,
			expirationDate: time.Now().Add(-24 * time.Hour),
			expectError:    false,
		},
		{
			name: "Future Token ID",
			config: verfiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			vin:            "1HGCM82633A123456",
			tokenID:        4294967295,
			expirationDate: time.Now().Add(24 * time.Hour),
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuerService, err := verfiable.NewIssuer(tt.config)
			require.NoError(t, err)

			vc, err := issuerService.CreateVINVC(tt.vin, tt.tokenID, tt.expirationDate)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			var credential verfiable.Credential
			err = json.Unmarshal(vc, &credential)
			require.NoError(t, err)
			var subject verfiable.VINSubject
			err = json.Unmarshal(credential.CredentialSubject, &subject)
			require.NoError(t, err)

			// Verify credential fields
			require.Equal(t, "https://www.w3.org/ns/credentials/v2", credential.Context[0])
			require.Equal(t, "https://schema.org", credential.Context[1])
			require.Equal(t, "urn:uuid:"+credential.ID[9:], credential.ID)
			require.Equal(t, "VerifiableCredential", credential.Type[0])
			require.Equal(t, "Vehicle", credential.Type[1])
			require.Equal(t, issuerService.DID(), credential.Issuer)
			require.Equal(t, tt.vin, subject.VehicleIdentificationNumber)
			require.Equal(t, tt.tokenID, parseTokenID(subject.ID))

			require.Contains(t, subject.ID, strconv.FormatInt(tt.config.ChainID.Int64(), 10))
			require.Contains(t, subject.ID, tt.config.VehicleNFTAddress.Hex())
			require.Contains(t, credential.CredentialStatus.ID, tt.config.BaseStatusURL)

			// Verify credential proof
			valid := validateProof(t, credential.Proof, credential, privateKey)
			require.True(t, valid)
		})
	}
}

func TestTamperedPayload(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	config := verfiable.Config{
		PrivateKey:        crypto.FromECDSA(privateKey),
		ChainID:           big.NewInt(1),
		VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		BaseStatusURL:     "https://status.example.com",
	}

	issuerService, err := verfiable.NewIssuer(config)
	require.NoError(t, err)

	// Create a valid VC
	vin := "1HGCM82633A123456"
	tokenID := uint32(1)
	expirationDate := time.Now().Add(24 * time.Hour)
	vc, err := issuerService.CreateVINVC(vin, tokenID, expirationDate)
	require.NoError(t, err)

	var origCredential verfiable.Credential
	var tamperedVIN verfiable.Credential
	var tamperedProof verfiable.Credential
	err = json.Unmarshal(vc, &origCredential)
	require.NoError(t, err)

	err = json.Unmarshal(vc, &tamperedVIN)
	require.NoError(t, err)

	err = json.Unmarshal(vc, &tamperedProof)
	require.NoError(t, err)

	badVin := "1HGCM82633A654321"
	var subject verfiable.VINSubject
	err = json.Unmarshal(tamperedVIN.CredentialSubject, &subject)
	require.NoError(t, err)
	subject.VehicleIdentificationNumber = badVin

	tamperedSubject, err := json.Marshal(subject)
	require.NoError(t, err)
	tamperedVIN.CredentialSubject = tamperedSubject

	// Verify tampered credential proof
	valid := validateProof(t, origCredential.Proof, tamperedVIN, privateKey)
	require.False(t, valid)

	// Tamper with the proof
	tamperedProof.Proof.Cryptosuite = "bad-cryptosuite"
	valid = validateProof(t, origCredential.Proof, tamperedProof, privateKey)
	require.False(t, valid)
}

// parseTokenID extracts the token ID from the credential subject ID.
func parseTokenID(id string) uint32 {
	// Example format: did:nft:<chainID>_erc721:<contractAddress>_<tokenID>
	parts := strings.Split(id, "_")
	if len(parts) < 3 {
		return 0
	}
	tokenIDStr := parts[2]
	tokenID, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(tokenID)
}

// checkProof verifies the proof of a credential.
func validateProof(t *testing.T, proof verfiable.Proof, credential verfiable.Credential, privateKey *ecdsa.PrivateKey) bool {
	// Canonicalize the credential
	ldProcessor := ld.NewJsonLdProcessor()
	ldOptions, err := verfiable.DefaultLdOptions()
	require.NoError(t, err)

	proofOptions := credential.Proof.ProofOptions
	credential.Proof = verfiable.Proof{}

	canonicalizedCredential, err := verfiable.Canonicalize(credential, ldProcessor, ldOptions)
	require.NoError(t, err)

	// Canonicalize the proof options
	config := verfiable.ProofOptionsWithContext{
		Context:      credential.Context,
		ProofOptions: proofOptions,
	}
	canonicalizedProofOptions, err := verfiable.Canonicalize(config, ldProcessor, ldOptions)
	require.NoError(t, err)

	// Hash the data
	hashData, err := verfiable.HashData(canonicalizedCredential, canonicalizedProofOptions)
	require.NoError(t, err)

	// Verify the signature
	signatureBytes := base58.Decode(proof.ProofValue)
	require.NotEmpty(t, signatureBytes)

	return ecdsa.VerifyASN1(&privateKey.PublicKey, hashData, signatureBytes)
}
