package config

import "github.com/DIMO-Network/clickhouse-infra/pkg/connect/config"

// Settings contains the application config.
type Settings struct {
	Port                      int    `yaml:"PORT"`
	MonPort                   int    `yaml:"MON_PORT"`
	DevicesAPIGRPCAddr        string `yaml:"DEVICES_APIGRPC_ADDR"`
	TokenExchangeJWTKeySetURL string `yaml:"TOKEN_EXCHANGE_JWK_KEY_SET_URL"`
	TokenExchangeIssuer       string `yaml:"TOKEN_EXCHANGE_ISSUER_URL"`
	VehicleNFTAddress         string `yaml:"VEHICLE_NFT_ADDRESS"`
	TelemetryURL              string `yaml:"TELEMETRY_URL"`
	FingerprintBucket         string `yaml:"FINGERPRINT_BUCKET"`
	FingerprintDataType       string `yaml:"FINGERPRINT_DATA_TYPE"`
	VINVCBucket               string `yaml:"VINVC_BUCKET"`
	VINVCDataType             string `yaml:"VINVC_DATA_TYPE"`
	IdentityAPIURL            string `yaml:"IDENTITY_API_URL"`
	AWSRegion                 string `yaml:"AWS_REGION"`
	PrivateKey                []byte `yaml:"PRIVATE_KEY"`
	DIMORegistryChainID       int64  `yaml:"DIMO_REGISTRY_CHAIN_ID"`
	ExternalHostname          string `yaml:"EXTERNAL_HOSTNAME"`
	RevokedTokenIDs           string `yaml:"REVOKED_TOKEN_IDS"`
	Clickhouse                config.Settings
}
