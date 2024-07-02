package verifiable_test

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
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
		config         verifiable.Config
		vin            string
		countryCode    string
		tokenID        uint32
		expirationDate time.Time
		expectError    bool
	}{
		{
			name: "Valid Config 1",
			config: verifiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			vin:            "1HGCM82633A123456",
			countryCode:    "US",
			tokenID:        1,
			expirationDate: time.Now().Add(24 * time.Hour),
			expectError:    false,
		},
		{
			name: "Valid Config 2",
			config: verifiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(2),
				VehicleNFTAddress: common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdef"),
				BaseStatusURL:     "https://status.example.org",
			},
			vin:            "1HGCM82633B654321",
			countryCode:    "CA",
			tokenID:        2,
			expirationDate: time.Now().Add(24 * time.Hour),
			expectError:    false,
		},
		{
			name: "Expired Date",
			config: verifiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			vin:            "1HGCM82633A123456",
			countryCode:    "US",
			tokenID:        1,
			expirationDate: time.Now().Add(-24 * time.Hour),
			expectError:    false,
		},
		{
			name: "Future Token ID",
			config: verifiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			vin:            "1HGCM82633A123456",
			countryCode:    "US",
			tokenID:        4294967295,
			expirationDate: time.Now().Add(24 * time.Hour),
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuerService, err := verifiable.NewIssuer(tt.config)
			require.NoError(t, err)
			fmt.Printf("%x\n", tt.config.PrivateKey)
			vc, err := issuerService.CreateVINVC(tt.vin, tt.countryCode, tt.tokenID, tt.expirationDate)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			var credential verifiable.Credential
			err = json.Unmarshal(vc, &credential)
			require.NoError(t, err)
			var subject verifiable.VINSubject
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
			pubKey, err := extractPublicKeyFromVerificationMethod(credential.Proof.VerificationMethod)
			require.NoError(t, err)
			valid := validateProof(t, credential.Proof, credential, pubKey)
			require.True(t, valid)
		})
	}
}

func TestCreateBitstringStatusListVC(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	tests := []struct {
		name        string
		config      verifiable.Config
		tokenID     uint32
		revoked     bool
		expectError bool
		expectedBit byte
	}{
		{
			name: "Valid BitstringStatusListCredential - Not Revoked",
			config: verifiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			tokenID:     1,
			revoked:     false,
			expectError: false,
			expectedBit: 1,
		},
		{
			name: "Valid BitstringStatusListCredential - Revoked",
			config: verifiable.Config{
				PrivateKey:        crypto.FromECDSA(privateKey),
				ChainID:           big.NewInt(1),
				VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				BaseStatusURL:     "https://status.example.com",
			},
			tokenID:     2,
			revoked:     true,
			expectError: false,
			expectedBit: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuerService, err := verifiable.NewIssuer(tt.config)
			require.NoError(t, err)

			vc, err := issuerService.CreateBitstringStatusListVC(tt.tokenID, tt.revoked)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			var credential verifiable.Credential
			err = json.Unmarshal(vc, &credential)
			require.NoError(t, err)

			// Verify credential fields
			require.Equal(t, "https://www.w3.org/ns/credentials/v2", credential.Context[0])
			require.Equal(t, issuerService.DID(), credential.Issuer)
			require.Equal(t, "VerifiableCredential", credential.Type[0])
			require.Equal(t, "BitstringStatusListCredential", credential.Type[1])

			var subject verifiable.BitstringStatusListSubject
			err = json.Unmarshal(credential.CredentialSubject, &subject)
			require.NoError(t, err)
			require.Equal(t, "BitstringStatusList", subject.Type)
			require.Equal(t, credential.ID+"#list", subject.ID)
			require.Equal(t, "revocation", subject.StatusPurpose)

			bitList, err := decodeAndDecompressBitList(subject.EncodedList)
			require.NoError(t, err)

			// Check if the bit list matches the expected bit
			for _, bit := range bitList {
				require.Equal(t, tt.expectedBit, bit)
			}

			// Verify credential proof
			pubKey, err := extractPublicKeyFromVerificationMethod(credential.Proof.VerificationMethod)
			require.NoError(t, err)
			valid := validateProof(t, credential.Proof, credential, pubKey)
			require.True(t, valid)
		})
	}
}

func TestTamperedPayload(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	config := verifiable.Config{
		PrivateKey:        crypto.FromECDSA(privateKey),
		ChainID:           big.NewInt(1),
		VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		BaseStatusURL:     "https://status.example.com",
	}

	issuerService, err := verifiable.NewIssuer(config)
	require.NoError(t, err)

	// Create a valid VC
	vin := "1HGCM82633A123456"
	tokenID := uint32(1)
	expirationDate := time.Now().Add(24 * time.Hour)
	vc, err := issuerService.CreateVINVC(vin, "US", tokenID, expirationDate)
	require.NoError(t, err)

	var origCredential verifiable.Credential
	var tamperedVIN verifiable.Credential
	var tamperedProof verifiable.Credential
	err = json.Unmarshal(vc, &origCredential)
	require.NoError(t, err)

	err = json.Unmarshal(vc, &tamperedVIN)
	require.NoError(t, err)

	err = json.Unmarshal(vc, &tamperedProof)
	require.NoError(t, err)

	badVin := "1HGCM82633A654321"
	var subject verifiable.VINSubject
	err = json.Unmarshal(tamperedVIN.CredentialSubject, &subject)
	require.NoError(t, err)
	subject.VehicleIdentificationNumber = badVin

	tamperedSubject, err := json.Marshal(subject)
	require.NoError(t, err)
	tamperedVIN.CredentialSubject = tamperedSubject

	// Verify tampered credential proof
	pubKey, err := extractPublicKeyFromVerificationMethod(origCredential.Proof.VerificationMethod)
	require.NoError(t, err)
	valid := validateProof(t, origCredential.Proof, tamperedVIN, pubKey)
	require.False(t, valid)

	// Tamper with the proof
	tamperedProof.Proof.Cryptosuite = "bad-cryptosuite"
	pubKey, err = extractPublicKeyFromVerificationMethod(origCredential.Proof.VerificationMethod)
	require.NoError(t, err)
	valid = validateProof(t, origCredential.Proof, tamperedProof, pubKey)
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

// extractPublicKeyFromVerificationMethod extracts and decodes the public key from the verification method.
func extractPublicKeyFromVerificationMethod(verificationMethod string) (*ecdsa.PublicKey, error) {
	parts := strings.Split(verificationMethod, "#")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid verification method")
	}
	encodedKey := strings.TrimPrefix(parts[1], "z")
	keyBytes := base58.Decode(encodedKey)
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("failed to decode base58 key")
	}
	// Decompress the key bytes
	pubKey := keyBytes[2:]
	pub, err := crypto.DecompressPubkey(pubKey)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// checkProof verifies the proof of a credential.
func validateProof(t *testing.T, proof verifiable.Proof, credential verifiable.Credential, publicKey *ecdsa.PublicKey) bool {
	// Canonicalize the credential
	ldProcessor := ld.NewJsonLdProcessor()
	ldOptions, err := verifiable.DefaultLdOptions()
	require.NoError(t, err)

	proofOptions := credential.Proof.ProofOptions
	credential.Proof = verifiable.Proof{}

	canonicalizedCredential, err := verifiable.Canonicalize(credential, ldProcessor, ldOptions)
	require.NoError(t, err)

	// Canonicalize the proof options
	config := verifiable.ProofOptionsWithContext{
		Context:      credential.Context,
		ProofOptions: proofOptions,
	}
	canonicalizedProofOptions, err := verifiable.Canonicalize(config, ldProcessor, ldOptions)
	require.NoError(t, err)

	// Hash the data
	hashData, err := verifiable.HashData(canonicalizedCredential, canonicalizedProofOptions)
	require.NoError(t, err)

	// Verify the signature
	signatureBytes := base58.Decode(proof.ProofValue)
	require.NotEmpty(t, signatureBytes)

	return ecdsa.VerifyASN1(publicKey, hashData, signatureBytes)
}

// decodeAndDecompressBitList decompresses and verifies the bit list.
func decodeAndDecompressBitList(encodedList string) ([]byte, error) {
	// Decode and verify the encoded list
	decodedList, err := base64.StdEncoding.DecodeString(encodedList)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}
	reader := bytes.NewReader(decodedList)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	decodedBitList, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from gzip reader: %w", err)
	}

	return decodedBitList, nil
}
