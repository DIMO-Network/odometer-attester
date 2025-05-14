package tokencache

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

// TokenGetter defines a function type for retrieving new tokens.
type TokenGetter interface {
	GetToken(ctx context.Context, key string) (string, error)
}

// Cache provides JWT token caching functionality.
type Cache struct {
	cache       *cache.Cache
	tokenGetter TokenGetter
}

// New creates a new token cache instance.
func New(defaultExpiration, cleanupInterval time.Duration, tokenGetter TokenGetter) *Cache {
	return &Cache{
		cache:       cache.New(defaultExpiration, cleanupInterval),
		tokenGetter: tokenGetter,
	}
}

// extractExpirationFromToken parses the JWT token and extracts its expiration time.
func extractExpirationFromToken(tokenString string) (time.Time, error) {
	// Parse the token without verifying the signature
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, fmt.Errorf("JWT token does not contain an expiration claim: %w", err)
	}

	return exp.Time, nil
}

// GetToken retrieves a token for the specified vehicle token ID
// If the token is not in the cache or has expired, it will fetch a new one.
func (c *Cache) GetToken(ctx context.Context, key string) (string, error) {
	if token, found := c.cache.Get(key); found {
		return token.(string), nil
	}

	// Token not found or expired, get a new one
	token, err := c.tokenGetter.GetToken(ctx, key)
	if err != nil {
		return "", fmt.Errorf("failed to get new token: %w", err)
	}
	// Extract expiration time from the JWT token
	expiry, err := extractExpirationFromToken(token)
	if err != nil {
		return "", fmt.Errorf("error extracting expiration from token: %w", err)
	}

	// Calculate duration until expiry
	// Set expiry to be slightly before the actual token expiry to ensure we don't use expired tokens
	expiryDuration := time.Until(expiry) - (30 * time.Second)
	if expiryDuration < 0 {
		expiryDuration = 0
	}

	// Store token in cache with expiry
	c.cache.Set(key, token, expiryDuration)

	return token, nil
}

// DevLicenseTokenKey returns a key for the specified dev license ID.
func DevLicenseTokenKey(devLicenseID string) string {
	return fmt.Sprintf("devlicense:%s", devLicenseID)
}

// DevLicenseTokenIDFromKey returns the dev license ID from the specified key.
func DevLicenseTokenIDFromKey(key string) (string, error) {
	parts := strings.Split(key, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid key format: %s", key)
	}
	return parts[1], nil
}

// VehicleTokenKey returns a key for the specified vehicle token ID.
func VehicleTokenKey(vehicleTokenID *big.Int) string {
	return fmt.Sprintf("vehicle:%d", vehicleTokenID)
}

// VehicleTokenIDFromKey returns the vehicle token ID from the specified key.
func VehicleTokenIDFromKey(key string) (uint32, error) {
	parts := strings.Split(key, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid key format: %s", key)
	}
	id, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid vehicle token ID: %w", err)
	}
	return uint32(id), nil
}
