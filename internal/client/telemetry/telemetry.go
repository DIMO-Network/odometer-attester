package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
)

const odometerQuery = `
query lastSeen($tokenId: Int!) {
	signalsLatest(tokenId: $tokenId) {
    lastSeen
    powertrainTransmissionTravelledDistance{
      timestamp
      value
    }
  }
}
`

// const odometerQueryInterval = `
// query interval($tokenId: Int!, $from: String!, $to: String!, $interval: String!) {
//    signals(
//     tokenId: $tokenId
//     from: $from
// 	to: $to
// 	interval: $interval
//   ) {
//     timestamp
// 		minDist powertrainTransmissionTravelledDistance(agg:Min)
// 		maxDist powertrainTransmissionTravelledDistance(agg:Max)
//   }
// }
// `

// Client interacts with the telemetry GraphQL API.
type Client struct {
	httpClient  *http.Client
	apiQueryURL string
	tokenCache  *tokencache.Cache
}

// NewClient creates a new instance of Client with optional TLS certificate pool.
func NewClient(apiBaseURL string, client *http.Client, tokenCache *tokencache.Cache) (*Client, error) {
	path, err := url.JoinPath(apiBaseURL, "query")
	if err != nil {
		return nil, fmt.Errorf("create telemetry URL: %w", err)
	}
	if client == nil {
		return nil, fmt.Errorf("HTTP client is nil")
	}

	return &Client{
		apiQueryURL: path,
		httpClient:  client,
		tokenCache:  tokenCache,
	}, nil
}

// GetOdometer fetches the latest odometer reading from the telemetry API.
func (c *Client) GetOdometer(ctx context.Context, tokenID *big.Int) (*OdometerResponse, error) {
	requestBody := map[string]any{
		"query": odometerQuery,
		"variables": map[string]any{
			"tokenId": tokenID,
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

	// Get JWT token from cache and add as Authorization header
	token, err := c.tokenCache.GetToken(ctx, tokencache.VehicleTokenKey(tokenID))
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

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

	return &respBody.Data.SignalsLatest, nil
}

// GetOdometerInLastInterval fetches the latest odometer reading from the telemetry API.
func (c *Client) GetOdometerInLastInterval(ctx context.Context, tokenID *big.Int, interval time.Duration) (*OdometerResponse, error) {
	requestBody := map[string]any{
		"query": odometerQuery,
		"variables": map[string]any{
			"tokenId": tokenID,
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

	// Get JWT token from cache and add as Authorization header
	token, err := c.tokenCache.GetToken(ctx, tokencache.VehicleTokenKey(tokenID))
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

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

	return &respBody.Data.SignalsLatest, nil
}
