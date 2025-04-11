package config

import "github.com/ethereum/go-ethereum/common"

// Settings contains the application config.
type Settings struct {
	Environment string `env:"ENVIRONMENT" yaml:"environment"`
	LogLevel    string `env:"LOG_LEVEL"   yaml:"logLevel"`
	Port        int    `env:"PORT"        yaml:"port"`
	MonPort     int    `env:"MON_PORT"    yaml:"monPort"`

	// Token Exchange settings
	TokenExchangeURL          string         `env:"TOKEN_EXCHANGE_URL"           yaml:"tokenExchangeUrl"`
	VehicleNFTContractAddress common.Address `env:"VEHICLE_NFT_CONTRACT_ADDRESS" yaml:"vehicleNftContractAddress"`
	DeveloperLicense          string         `env:"DEVELOPER_LICENSE"            yaml:"developerLicense"`
	ChainID                   uint64         `env:"CHAIN_ID"                      yaml:"chainId"`
	// Dex settings
	DexURL     string `env:"DEX_URL"     yaml:"dexUrl"`
	PrivateKey string `env:"PRIVATE_KEY" yaml:"privateKey"`

	// API URLs
	TelemetryAPIURL string `env:"TELEMETRY_API_URL" yaml:"telemetryApiUrl"`
	IdentityAPIURL  string `env:"IDENTITY_API_URL"  yaml:"identityApiUrl"`

	// Dev fake key
	DevFakeKey string `env:"DEV_FAKE_KEY" yaml:"devFakeKey"`
}
