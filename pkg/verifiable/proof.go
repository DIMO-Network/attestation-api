package verifiable

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcsuite/btcutil/base58"
	"github.com/piprate/json-gold/ld"
)

const (
	Format             = "application/n-quads"
	AlgorithmURDNA2015 = "URDNA2015"
	procMode           = "json-ld-1.1"
	// ecdsaRdfc2019 is the cryptosuite used for ecdsa-rdfc-2019.
	ecdsaRdfc2019      = "ecdsa-rdfc-2019"
	dataIntegrityProof = "DataIntegrityProof"
)

// CreateProof creates a proof for a document using ecdsa-rdfc-2019.
func CreateProof(unsecuredDocument Credential, options ProofOptions, privateKey *ecdsa.PrivateKey, ldProcessor *ld.JsonLdProcessor, ldOptions *ld.JsonLdOptions) (Proof, error) {
	proof := Proof{
		ProofOptions: options,
	}
	if options.Type != dataIntegrityProof || options.Cryptosuite != ecdsaRdfc2019 {
		return proof, fmt.Errorf("PROOF_TRANSFORMATION_ERROR: invalid type or cryptosuite")
	}

	// Generate proof configuration
	config := ProofOptionsWithContext{
		Context:      unsecuredDocument.Context,
		ProofOptions: options,
	}
	transformedConfig, err := Canonicalize(config, ldProcessor, ldOptions)
	if err != nil {
		return proof, fmt.Errorf("failed to generate proof configuration: %w", err)
	}

	// Transform the data
	transformedDoc, err := Canonicalize(unsecuredDocument, ldProcessor, ldOptions)
	if err != nil {
		return proof, fmt.Errorf("failed to transform data: %w", err)
	}

	// Hash the data
	hashData, err := HashData(transformedDoc, transformedConfig)
	if err != nil {
		return proof, fmt.Errorf("failed to hash data: %w", err)
	}

	// Sign the data
	signature, err := signData(hashData, privateKey, options.Cryptosuite)
	if err != nil {
		return proof, fmt.Errorf("failed to sign data: %w", err)
	}
	proof.ProofValue = base58.Encode(signature)
	return proof, nil
}

// Canonicalize canonicalizes the data using the given processor and options.
func Canonicalize(data any, ldProc *ld.JsonLdProcessor, ldOptions *ld.JsonLdOptions) ([]byte, error) {
	mappedData := make(map[string]any)
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	if err := json.Unmarshal(jsonData, &mappedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}
	canonacalDoc, err := ldProc.Normalize(mappedData, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize data: %w", err)
	}
	canonacalStr, ok := canonacalDoc.(string)
	if !ok {
		return nil, fmt.Errorf("failed to convert canonicalized data to string")
	}
	return []byte(canonacalStr), nil
}

// HashData hashes the canonicalized data.
func HashData(transformedData, proofConfig []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to write proof config to hash: %w", err)
	}
	_, err = hash.Write(transformedData)
	if err != nil {
		return nil, fmt.Errorf("failed to write transformed data to hash: %w", err)
	}
	return hash.Sum(nil), nil
}

// signData signs the hash data using ECDSA.
func signData(hashData []byte, privateKey *ecdsa.PrivateKey, cryptosuite string) ([]byte, error) {
	var signature []byte
	var err error

	switch cryptosuite {
	case ecdsaRdfc2019:
		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, hashData)
		if err != nil {
			return nil, fmt.Errorf("failed to sign hash: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported cryptosuite: %s", cryptosuite)
	}

	return signature, nil
}

func DefaultDocumentLoader(localSchemaURL, localSchema string) (ld.DocumentLoader, error) {
	docLoader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(nil))
	localSchemaFile, err := os.CreateTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp local schema file: %w", err)
	}
	if _, err := localSchemaFile.Write([]byte(localSchema)); err != nil {
		return nil, fmt.Errorf("failed to write to temp local schema file: %w", err)
	}
	if err := localSchemaFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp local schema file: %w", err)
	}

	err = docLoader.PreloadWithMapping(map[string]string{
		localSchemaURL: localSchemaFile.Name(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to preload with mapping: %w", err)
	}
	return docLoader, nil
}

// DefaultLdOptions returns the default JSON-LD options.
func DefaultLdOptions(localSchemaURL, localSchema string) (*ld.JsonLdOptions, error) {
	options := ld.NewJsonLdOptions("")
	options.Format = Format
	options.Algorithm = AlgorithmURDNA2015
	options.ProcessingMode = procMode
	options.ProduceGeneralizedRdf = true
	docLoader, err := DefaultDocumentLoader(localSchemaURL, localSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to create document loader: %w", err)
	}
	options.DocumentLoader = docLoader
	return options, nil
}
