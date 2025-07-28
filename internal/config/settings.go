package config

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Settings contains the application config.
type Settings struct {
	Port                      int    `env:"PORT"`
	MonPort                   int    `env:"MON_PORT"`
	EnablePprof               bool   `env:"ENABLE_PPROF"`
	GRPCPort                  int    `env:"GRPC_PORT"`
	DefinitionsGRPCAddr       string `env:"DEFINITIONS_GRPC_ADDR"`
	TokenExchangeJWTKeySetURL string `env:"TOKEN_EXCHANGE_JWK_KEY_SET_URL"`
	TokenExchangeIssuer       string `env:"TOKEN_EXCHANGE_ISSUER_URL"`
	VehicleNFTAddress         string `env:"VEHICLE_NFT_ADDRESS"`
	AfterMarketNFTAddress     string `env:"AFTERMARKET_NFT_ADDRESS"`
	SyntheticNFTAddress       string `env:"SYNTHETIC_NFT_ADDRESS"`
	TelemetryURL              string `env:"TELEMETRY_URL"`
	IdentityAPIURL            string `env:"IDENTITY_API_URL"`
	DIMORegistryChainID       int64  `env:"DIMO_REGISTRY_CHAIN_ID"`
	DISURL                    string `env:"DIS_URL"`
	SignerPrivateKey          string `env:"SIGNER_PRIVATE_KEY"`
	DexURL                    string `env:"DEX_URL"`
	DevLicense                string `env:"DEV_LICENSE"`
	FetchGRPCAddr             string `env:"FETCH_GRPC_ADDR"`
	RedirectURL               string `env:"DEV_LICENSE_REDIRECT_URL"`
	VINDataVersion            string `env:"VIN_DATA_VERSION"`

	SubjectsList     string `env:"SUBJECTS_LIST"`
	ConcurrencyLimit int    `env:"CONCURRENCY_LIMIT"`
}

// LoadSettings loads the settings from environment variables or .env file.
func LoadSettings(filePath string) (*Settings, error) {
	settings := &Settings{}

	// First try to populate env variables from .env file if it exists.
	if _, err := os.Stat(filePath); err == nil {
		err = godotenv.Load(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load settings from %s: %w", filePath, err)
		}
	}

	if err := env.Parse(settings); err != nil {
		return nil, fmt.Errorf("failed to parse settings from environment variables: %w", err)
	}

	return settings, nil
}
