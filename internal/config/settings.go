package config

import (
	"github.com/DIMO-Network/enclave-bridge/pkg/config"
	"github.com/ethereum/go-ethereum/common"
)

// Settings contains the application config.
type Settings struct {
	Environment string `env:"ENVIRONMENT"    yaml:"environment"`
	LogLevel    string `env:"LOG_LEVEL"      yaml:"logLevel"`
	Port        int    `env:"PORT"           yaml:"port"`
	MonPort     int    `env:"MON_PORT"       yaml:"monPort"`

	// Token Exchange settings
	VehicleNFTContractAddress common.Address `env:"VEHICLE_NFT_CONTRACT_ADDRESS" yaml:"vehicleNftContractAddress"`
	DeveloperLicense          string         `env:"DEVELOPER_LICENSE"            yaml:"developerLicense"`
	ChainID                   uint64         `env:"CHAIN_ID"                     yaml:"chainId"`
	// Dex settings
	PrivateKey string `env:"PRIVATE_KEY" yaml:"privateKey"`

	// API URLs
	TokenExchangeURL  string `env:"TOKEN_EXCHANGE_URL" yaml:"tokenExchangeUrl"`
	DexURL            string `env:"DEX_URL"            yaml:"dexUrl"`
	TelemetryAPIURL   string `env:"TELEMETRY_API_URL"  yaml:"telemetryApiUrl"`
	IdentityAPIURL    string `env:"IDENTITY_API_URL"   yaml:"identityApiUrl"`
	SignerRegistryURL string `env:"SIGNER_REGISTRY_URL" yaml:"signerRegistryUrl"`
	EthereumRPCURL    string `env:"ETHEREUM_RPC_URL"    yaml:"ethereumRpcUrl"`

	// Dev fake key
	DevFakeKey string `env:"DEV_FAKE_KEY" yaml:"devFakeKey"`

	TLS config.TLSConfig `envPrefix:"TLS_"`
}
