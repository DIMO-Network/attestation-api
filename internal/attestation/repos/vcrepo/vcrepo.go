package vcrepo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/DIMO-Network/attestation-api/internal/client/tokencache"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/crypto"
)

// Repo manages storing and retrieving VCs.
type Repo struct {
	disURL     *url.URL
	tokenCache *tokencache.Cache
	devLicense string
	privateKey *ecdsa.PrivateKey
}

// New creates a new instance of VCRepo.
func New(settings *config.Settings, tokenCache *tokencache.Cache) (*Repo, error) {
	disURL, err := url.Parse(settings.DISURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DIS URL: %w", err)
	}
	privateKey, err := crypto.HexToECDSA(settings.SignerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to ECDSA: %w", err)
	}
	return &Repo{
		disURL:     disURL,
		tokenCache: tokenCache,
		devLicense: settings.DevLicense,
		privateKey: privateKey,
	}, nil
}

// UploadAttestation uploads a new attestation to DIS.
func (r *Repo) UploadAttestation(ctx context.Context, attestation *cloudevent.RawEvent) error {
	eventBytes, err := json.Marshal(attestation)
	if err != nil {
		return fmt.Errorf("failed to marshal cloud event: %w", err)
	}

	token, err := r.tokenCache.GetToken(ctx, r.devLicense)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.disURL.String(), bytes.NewBuffer(eventBytes))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Check status code
	if resp.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DIS returned non-200 status code: %d; %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
