package config

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"gopkg.in/yaml.v3"
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
}

func LoadSettings(filePath string) (*Settings, error) {
	settings := &Settings{}

	// First try to load from settings.yaml
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read settings from %s: %w", filePath, err)
		}

		var yamlMap map[string]string
		if err := yaml.Unmarshal(data, &yamlMap); err != nil {
			return nil, fmt.Errorf("failed to parse settings from %s: %w", filePath, err)
		}

		opts := env.Options{
			Environment: yamlMap,
		}

		if err := env.ParseWithOptions(settings, opts); err != nil {
			return nil, fmt.Errorf("failed to parse settings from %s: %w", filePath, err)
		}
		return settings, nil
	}

	// Then override with environment variables
	if err := env.Parse(settings); err != nil {
		return nil, fmt.Errorf("failed to parse settings from environment variables: %w", err)
	}

	return settings, nil
}
