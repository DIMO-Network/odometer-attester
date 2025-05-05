package dis

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
	"github.com/DIMO-Network/odometer-attester/internal/config"
)

// Client is a client for interacting with the token exchange API.
type Client struct {
	httpClient   *http.Client
	disAPIURL    string
	tokenCache   *tokencache.Cache
	devLicenseID string
}

// NewClient creates a new instance of Client with all config from settings.
func NewClient(settings *config.Settings, tokenCache *tokencache.Cache, httpClient *http.Client) (*Client, error) {
	// Validate required settings
	if tokenCache == nil {
		return nil, fmt.Errorf("token cache is required")
	}

	if settings.DISAPIURL == "" {
		return nil, fmt.Errorf("DIS base URL is required")
	}

	if settings.DeveloperLicense == "" {
		return nil, fmt.Errorf("dev license ID is required")
	}

	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}

	// Create DIS API URL
	disAPIURL, err := url.JoinPath(settings.DISAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create DIS API URL: %w", err)
	}

	return &Client{
		httpClient:   httpClient,
		disAPIURL:    disAPIURL,
		tokenCache:   tokenCache,
		devLicenseID: settings.DeveloperLicense,
	}, nil
}

// UploadAttestation uploads the attestation to the DIS API.
func (c *Client) UploadAttestation(ctx context.Context, doc []byte) error {
	// Get the dev license token from the token cache
	devLicenseToken, err := c.tokenCache.GetToken(ctx, tokencache.DevLicenseTokenKey(c.devLicenseID))
	if err != nil {
		return fmt.Errorf("failed to get dev license token: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.disAPIURL, bytes.NewBuffer(doc))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+devLicenseToken)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Check status code
	if resp.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DIS returned non-200 status code: %d; %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
