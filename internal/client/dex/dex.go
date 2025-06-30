package dex

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/erc191"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	generateChallengeURI = "auth/web3/generate_challenge"
	submitChallengeURI   = "auth/web3/submit_challenge"
	domain               = "http://127.0.0.1:10000"
)

// ChallengeResponse represents the response from the generate challenge endpoint.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	State     string `json:"state"`
}

// TokenResponse represents the response from the submit challenge endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

// Client is a client for interacting with the Dex JWT server.
type Client struct {
	dexURL     *url.URL
	privateKey *ecdsa.PrivateKey
	client     *http.Client
}

// NewClient creates a new Dex client.
func NewClient(settings *config.Settings) (*Client, error) {
	privateKey, err := crypto.HexToECDSA(settings.SignerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error converting private key to ECDSA: %w", err)
	}

	dexURL, err := url.Parse(settings.DexURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing Dex URL: %w", err)
	}

	return &Client{
		dexURL:     dexURL,
		privateKey: privateKey,
		client:     http.DefaultClient,
	}, nil
}

// GetToken retrieves a developer license token from the Dex server with context.
func (c *Client) GetToken(ctx context.Context, devLicense string) (string, error) {

	// Init/generate challenge
	initParams := url.Values{}
	initParams.Set("domain", domain)
	initParams.Set("client_id", devLicense)
	initParams.Set("response_type", "code")
	initParams.Set("scope", "openid email")
	initParams.Set("address", devLicense)

	// Create challenge endpoint URL
	challengeURL, err := url.Parse(c.dexURL.String() + generateChallengeURI)
	if err != nil {
		return "", fmt.Errorf("error creating challenge URL: %w", err)
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, challengeURL.String(), strings.NewReader(initParams.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating challenge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error generating challenge: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error generating challenge: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	var challengeResponse ChallengeResponse
	err = json.Unmarshal(body, &challengeResponse)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %w", err)
	}
	challenge := challengeResponse.Challenge

	// Hash and sign challenge
	signedChallenge, err := erc191.SignMessage(challenge, c.privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing challenge: %w", err)
	}

	// Submit challenge
	state := challengeResponse.State
	submitParams := url.Values{}
	submitParams.Set("client_id", devLicense)
	submitParams.Set("domain", domain)
	submitParams.Set("grant_type", "authorization_code")
	submitParams.Set("state", state)
	submitParams.Set("signature", signedChallenge)

	// Create submit endpoint URL
	submitURL, err := url.Parse(c.dexURL.String() + submitChallengeURI)
	if err != nil {
		return "", fmt.Errorf("error creating submit URL: %w", err)
	}

	// Create request with context for submitting challenge
	submitReq, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL.String(), strings.NewReader(submitParams.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating submit request: %w", err)
	}
	submitReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	submitResp, err := http.DefaultClient.Do(submitReq)
	if err != nil {
		return "", fmt.Errorf("error submitting challenge: %w", err)
	}
	defer submitResp.Body.Close() //nolint:errcheck

	if submitResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(submitResp.Body)
		return "", fmt.Errorf("dex returned non-200 status code: %d; %s", submitResp.StatusCode, string(bodyBytes))
	}

	submitBody, err := io.ReadAll(submitResp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	// Extract 'access_token' from the response body
	var tokenResp TokenResponse
	if err := json.Unmarshal(submitBody, &tokenResp); err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return tokenResp.AccessToken, nil
}
