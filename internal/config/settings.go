package config

// Settings contains the application config.
type Settings struct {
	Port                      int    `env:"PORT"`
	MonPort                   int    `env:"MON_PORT"`
	EnablePprof               bool   `env:"ENABLE_PPROF"`
	GRPCPort                  int    `env:"GRPC_PORT"`
	DefinitionsGRPCAddr       string `env:"DEFINITIONS_GRPC_ADDR"`
	TokenExchangeJWTKeySetURL string `env:"TOKEN_EXCHANGE_JWK_KEY_SET_URL"`
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
