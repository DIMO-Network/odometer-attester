package config

import "github.com/ethereum/go-ethereum/common"

// Settings contains the application config.
type Settings struct {
	Environment string `env:"ENVIRONMENT" yaml:"environment"`
	LogLevel    string `env:"LOG_LEVEL"   yaml:"logLevel"`
	Port        int    `env:"PORT"        yaml:"port"`
	MonPort     int    `env:"MON_PORT"    yaml:"monPort"`
	EnclaveCID  uint32 `env:"ENCLAVE_CID" yaml:"enclaveCid"`

	// Token Exchange settings
	TokenExchangeBaseURL      string         `env:"TOKEN_EXCHANGE_BASE_URL"      yaml:"tokenExchangeBaseUrl"`
	VehicleNFTContractAddress common.Address `env:"VEHICLE_NFT_CONTRACT_ADDRESS" yaml:"vehicleNftContractAddress"`
	DeveloperLicenseID        string         `env:"DEVELOPER_LICENSE_ID"         yaml:"developerLicenseId"`

	// Dex settings
	DexURL     string `env:"DEX_URL"     yaml:"dexUrl"`
	PrivateKey string `env:"PRIVATE_KEY" yaml:"privateKey"`

	// API URLs
	TelemetryAPIURL string `env:"TELEMETRY_API_URL" yaml:"telemetryApiUrl"`
	IdentityAPIURL  string `env:"IDENTITY_API_URL"  yaml:"identityApiUrl"`
}
