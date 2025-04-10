// Package identity provides functionality to interact with the identity GraphQL API.
package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client interacts with the identity GraphQL API.
type Client struct {
	httpClient  *http.Client
	apiQueryURL string
}

// NewClient creates a new instance of Client with optional TLS certificate pool.
func NewClient(apiBaseURL string, client *http.Client) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("client is nil")
	}
	path, err := url.JoinPath(apiBaseURL, "query")
	if err != nil {
		return nil, fmt.Errorf("create idenitiy URL: %w", err)
	}

	return &Client{
		apiQueryURL: path,
		httpClient:  client,
	}, nil
}

// GetVehicleInfo fetches vehicle information from the identity API.
func (c *Client) GetVehicleInfo(ctx context.Context, vehicleTokenID uint32) (*GraphQLResponse, error) {
	requestBody := map[string]any{
		"query": query,
		"variables": map[string]any{
			"tokenId": vehicleTokenID,
		},
	}

	reqBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiQueryURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send GraphQL request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // ignore error

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 response from GraphQL API: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GraphQL response body: %w", err)
	}

	var respBody GraphQLResponse
	if err := json.Unmarshal(bodyBytes, &respBody); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL response: %w", err)
	}

	if len(respBody.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL API error: %s", respBody.Errors[0].Message)
	}
	return &respBody, nil
}
