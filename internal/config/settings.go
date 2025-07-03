package config

import "github.com/DIMO-Network/clickhouse-infra/pkg/connect/config"

// Settings contains the application config.
type Settings struct {
	Port                      int    `yaml:"PORT"`
	MonPort                   int    `yaml:"MON_PORT"`
	GRPCPort                  int    `yaml:"GRPC_PORT"`
	DefinitionsGRPCAddr       string `yaml:"DEFINITIONS_GRPC_ADDR"`
	TokenExchangeJWTKeySetURL string `yaml:"TOKEN_EXCHANGE_JWK_KEY_SET_URL"`
	TokenExchangeIssuer       string `yaml:"TOKEN_EXCHANGE_ISSUER_URL"`
	VehicleNFTAddress         string `yaml:"VEHICLE_NFT_ADDRESS"`
	AfterMarketNFTAddress     string `yaml:"AFTERMARKET_NFT_ADDRESS"`
	SyntheticNFTAddress       string `yaml:"SYNTHETIC_NFT_ADDRESS"`
	TelemetryURL              string `yaml:"TELEMETRY_URL"`
	VCBucket                  string `yaml:"VC_BUCKET"`
	POMVCDataType             string `yaml:"POMVC_DATA_TYPE"`
	CloudEventBucket          string `yaml:"CLOUDEVENT_BUCKET"`
	AutoPiDataType            string `yaml:"AUTOPI_DATA_TYPE"`
	AutoPiBucketName          string `yaml:"AUTOPI_BUCKET_NAME"`
	HashDogDataType           string `yaml:"HASHDOG_DATA_TYPE"`
	HashDogBucketName         string `yaml:"HASHDOG_BUCKET_NAME"`
	StatusDataType            string `yaml:"STATUS_DATA_TYPE"`
	StatusBucketName          string `yaml:"STATUS_BUCKET_NAME"`
	IdentityAPIURL            string `yaml:"IDENTITY_API_URL"`
	VINVCPrivateKey           string `yaml:"VIN_ISSUER_PRIVATE_KEY"`
	DIMORegistryChainID       int64  `yaml:"DIMO_REGISTRY_CHAIN_ID"`
	DISURL                    string `yaml:"DIS_URL"`
	SignerPrivateKey          string `yaml:"SIGNER_PRIVATE_KEY"`
	DexURL                    string `yaml:"DEX_URL"`
	DevLicense                string `yaml:"DEV_LICENSE"`
	FetchGRPCAddr             string `yaml:"FETCH_GRPC_ADDR"`
	RedirectURL               string `yaml:"DEV_LICENSE_REDIRECT_URL"`
	VINDataVersion            string `yaml:"VIN_DATA_VERSION"`

	// TODO (kevin): Remove with smartcar deprecation
	Clickhouse           config.Settings `yaml:",inline"`
	FingerprintBucket    string          `yaml:"FINGERPRINT_BUCKET"`
	FingerprintDataType  string          `yaml:"FINGERPRINT_DATA_TYPE"`
	S3AWSRegion          string          `yaml:"S3_AWS_REGION"`
	S3AWSAccessKeyID     string          `yaml:"S3_AWS_ACCESS_KEY_ID"`
	S3AWSSecretAccessKey string          `yaml:"S3_AWS_SECRET_ACCESS_KEY"`
}
