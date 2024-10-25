package config

import "github.com/DIMO-Network/clickhouse-infra/pkg/connect/config"

// Settings contains the application config.
type Settings struct {
	Port                      int             `yaml:"PORT"`
	MonPort                   int             `yaml:"MON_PORT"`
	DefinitionsGRPCAddr       string          `yaml:"DEFINITIONS_GRPC_ADDR"`
	TokenExchangeJWTKeySetURL string          `yaml:"TOKEN_EXCHANGE_JWK_KEY_SET_URL"`
	TokenExchangeIssuer       string          `yaml:"TOKEN_EXCHANGE_ISSUER_URL"`
	VehicleNFTAddress         string          `yaml:"VEHICLE_NFT_ADDRESS"`
	AfterMarketNFTAddress     string          `yaml:"AFTERMARKET_NFT_ADDRESS"`
	SyntheticNFTAddress       string          `yaml:"SYNTHETIC_NFT_ADDRESS"`
	TelemetryURL              string          `yaml:"TELEMETRY_URL"`
	FingerprintBucket         string          `yaml:"FINGERPRINT_BUCKET"`
	FingerprintDataType       string          `yaml:"FINGERPRINT_DATA_TYPE"`
	VINVCBucket               string          `yaml:"VINVC_BUCKET"`
	VINVCDataType             string          `yaml:"VINVC_DATA_TYPE"`
	POMVCBucket               string          `yaml:"POMVC_BUCKET"`
	POMVCDataType             string          `yaml:"POMVC_DATA_TYPE"`
	CloudEventBucket          string          `yaml:"CLOUDEVENT_BUCKET"`
	AutoPiDataType            string          `yaml:"AUTOPI_DATA_TYPE"`
	AutoPiBucketName          string          `yaml:"AUTOPI_BUCKET_NAME"`
	HashDogDataType           string          `yaml:"HASHDOG_DATA_TYPE"`
	HashDogBucketName         string          `yaml:"HASHDOG_BUCKET_NAME"`
	StatusDataType            string          `yaml:"STATUS_DATA_TYPE"`
	StatusBucketName          string          `yaml:"STATUS_BUCKET_NAME"`
	IdentityAPIURL            string          `yaml:"IDENTITY_API_URL"`
	S3AWSRegion               string          `yaml:"S3_AWS_REGION"`
	S3AWSAccessKeyID          string          `yaml:"S3_AWS_ACCESS_KEY_ID"`
	S3AWSSecretAccessKey      string          `yaml:"S3_AWS_SECRET_ACCESS_KEY"`
	VINVCPrivateKey           string          `yaml:"VIN_ISSUER_PRIVATE_KEY"`
	DIMORegistryChainID       int64           `yaml:"DIMO_REGISTRY_CHAIN_ID"`
	ExternalHostname          string          `yaml:"EXTERNAL_HOSTNAME"`
	RevokedTokenIDs           string          `yaml:"REVOKED_TOKEN_IDS"`
	Clickhouse                config.Settings `yaml:",inline"`
}
