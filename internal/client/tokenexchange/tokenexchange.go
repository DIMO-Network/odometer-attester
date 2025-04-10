package tokenexchange

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

const (
	tokenExchangeEndpoint = "/v1/tokens/exchange" //nolint:gosec
)

// ExchangeRequest represents the request body for the token exchange API.
type ExchangeRequest struct {
	NFTContractAddress string                 `json:"nftContractAddress"`
	Privileges         []privileges.Privilege `json:"privileges"`
	TokenID            uint32                 `json:"tokenId"`
}

// Client is a client for interacting with the token exchange API.
type Client struct {
	httpClient         *http.Client
	tokenExchangeURL   string
	tokenCache         *tokencache.Cache
	nftContractAddress common.Address
	devLicenseID       string
	logger             *zerolog.Logger
}

// NewClient creates a new instance of Client with all config from settings.
func NewClient(settings *config.Settings, tokenCache *tokencache.Cache, httpClient *http.Client, logger zerolog.Logger) (*Client, error) {
	// Validate required settings
	if tokenCache == nil {
		return nil, fmt.Errorf("token cache is required")
	}

	if settings.TokenExchangeURL == "" {
		return nil, fmt.Errorf("token exchange base URL is required")
	}

	if settings.DeveloperLicense == "" {
		return nil, fmt.Errorf("dev license ID is required")
	}

	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}

	// Create token exchange URL
	tokenExchangeURL, err := url.JoinPath(settings.TokenExchangeURL, tokenExchangeEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange URL: %w", err)
	}

	return &Client{
		httpClient:         httpClient,
		tokenExchangeURL:   tokenExchangeURL,
		tokenCache:         tokenCache,
		nftContractAddress: settings.VehicleNFTContractAddress,
		devLicenseID:       settings.DeveloperLicense,
		logger:             &logger,
	}, nil
}

// GetToken implements the tokencache.TokenGetter interface.
func (c *Client) GetToken(ctx context.Context, key string) (string, error) {
	// Extract the token ID from the key
	tokenID, err := tokencache.VehicleTokenIDFromKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to extract token ID from key: %w", err)
	}

	// Get the dev license token from the token cache
	devLicenseKey := tokencache.DevLicenseTokenKey(c.devLicenseID)
	devLicenseToken, err := c.tokenCache.GetToken(ctx, devLicenseKey)
	if err != nil {
		return "", fmt.Errorf("failed to get dev license token: %w", err)
	}

	// Create request body
	request := ExchangeRequest{
		NFTContractAddress: c.nftContractAddress.Hex(),
		Privileges:         []privileges.Privilege{privileges.VehicleNonLocationData},
		TokenID:            tokenID,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenExchangeURL, bytes.NewBuffer(requestBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+devLicenseToken)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Check status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange API returned non-200 status code: %d; %s", resp.StatusCode, string(bodyBytes))
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response - the API returns the token directly as a string
	var responseToken string
	if err := json.Unmarshal(bodyBytes, &responseToken); err != nil {
		// Try parsing as an object with a token field
		var tokenResponse struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
			return "", fmt.Errorf("failed to unmarshal response body: %w", err)
		}
		responseToken = tokenResponse.Token
	}

	return responseToken, nil
}
