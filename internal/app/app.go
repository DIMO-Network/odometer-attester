package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DIMO-Network/enclave-bridge/pkg/client"
	"github.com/DIMO-Network/odometer-attester/internal/client/dex"
	"github.com/DIMO-Network/odometer-attester/internal/client/identity"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokenexchange"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/DIMO-Network/odometer-attester/internal/tmp/acme"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
)

// CreateEnclaveWebServer creates a new web server with the given logger and settings.
func CreateEnclaveWebServer(logger *zerolog.Logger, clientPort, challengePort uint32, settings *config.Settings) (*fiber.App, *tls.Config, error) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, logger)
		},
		DisableStartupMessage: true,
	})
	// Setup HTTP client
	httpClient := client.NewHTTPClient(clientPort, nil)

	walletPrivateKey, certPrivateKey, err := GetKeys(settings, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get keys: %w", err)
	}

	certLogger := logger.With().Str("component", "acme").Logger()
	// Configure our ACME cert manager and get a certificate using ACME!
	certService, err := acme.NewCertManager(acme.CertManagerConfig{
		Domains:    []string{settings.HostName},
		Email:      settings.Email,
		Key:        certPrivateKey,
		CADirURL:   settings.CADirURL,
		HTTPClient: httpClient,
		Logger:     &certLogger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ACME cert manager: %w", err)
	}

	// TODO(kevin): this needs to be moved
	go func() {
		err = certService.Start(context.TODO(), logger)
		if err != nil {
			logger.Err(err).Msg("failed to start ACME cert manager")
		}
	}()

	// Setup the controller with all its dependencies
	ctrl, err := setupController(logger, settings, httpClient, walletPrivateKey, certService.GetCertificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup controller: %w", err)
	}

	app.Use(recover.New(recover.Config{
		Next:              nil,
		EnableStackTrace:  true,
		StackTraceHandler: nil,
	}))
	app.Use(cors.New())
	app.Get("/", HealthCheck)
	app.Get("/forward", func(ctx *fiber.Ctx) error {
		logger.Debug().Msg("Forward request received")
		msg := ctx.Query("msg")
		if msg == "" {
			msg = "Hello, World!"
		}
		return ctx.JSON(map[string]string{"data": "Hello From The Enclave! Did you say: " + msg})
	})
	app.Get("/.well-known/nsm-attestation", ctrl.GetNSMAttestations)
	app.Get("/vehicle/:tokenId", ctrl.GetVehicleInfo)
	app.Get("/vehicle/:tokenId/odometer", ctrl.GetOdometer)
	app.Get("/keys", ctrl.GetKeys)
	app.Get("/keys/unsafe", func(ctx *fiber.Ctx) error {
		return ctx.JSON(map[string]string{
			"certPublicKey": hex.EncodeToString(crypto.FromECDSAPub(&certPrivateKey.PublicKey)),
			"pk":            hex.EncodeToString(crypto.FromECDSA(walletPrivateKey)),
			"pub":           hex.EncodeToString(crypto.FromECDSAPub(&walletPrivateKey.PublicKey)),
			"pubAddr":       crypto.PubkeyToAddress(walletPrivateKey.PublicKey).Hex(),
		})
	})
	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1", "acme-tls/1"},
		GetCertificate: certService.GetCertificate,
	}
	return app, tlsConfig, nil
}

// HealthCheck godoc
// @Summary Show the status of server.
// @Description get the status of server.
// @Tags root
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router / [get]
func HealthCheck(ctx *fiber.Ctx) error {
	res := map[string]any{
		"data": "Server is up and running",
	}

	return ctx.JSON(res)
}

// ErrorHandler custom handler to log recovered errors using our logger and return json instead of string.
func ErrorHandler(ctx *fiber.Ctx, err error, logger *zerolog.Logger) error {
	code := fiber.StatusInternalServerError // Default 500 statuscode
	message := "Internal error."

	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
		message = e.Message
	}

	// don't log not found errors
	if code != fiber.StatusNotFound {
		logger.Err(err).Int("httpStatusCode", code).
			Str("httpPath", strings.TrimPrefix(ctx.Path(), "/")).
			Str("httpMethod", ctx.Method()).
			Msg("caught an error from http request")
	}

	return ctx.Status(code).JSON(codeResp{Code: code, Message: message})
}

type codeResp struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func GetKeys(settings *config.Settings, logger *zerolog.Logger) (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert private key: %w", err)
	}
	var walletPrivateKey *ecdsa.PrivateKey
	walletPk := settings.DevFakeKey
	if walletPk == "" {
		walletPrivateKey, err = crypto.GenerateKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate wallet private key: %w", err)
		}
	} else {
		logger.Warn().Msgf("Using unsafe injected key: %s", walletPk)
		walletPrivateKey, err = crypto.HexToECDSA(walletPk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert hex to ecdsa private key: %w", err)
		}
	}
	return walletPrivateKey, certPrivateKey, nil
}

// setupController creates and configures all the clients needed for the controller.
func setupController(logger *zerolog.Logger, settings *config.Settings, httpClient *http.Client, privateKey *ecdsa.PrivateKey, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*Controller, error) {
	// Setup identity client
	identClient, err := identity.NewClient(settings.IdentityAPIURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity client: %w", err)
	}

	// Setup dex client for developer license tokens
	dexClient, err := dex.NewClient(settings, privateKey, httpClient, logger.With().Str("component", "dex").Logger())
	if err != nil {
		return nil, fmt.Errorf("failed to create dex client: %w", err)
	}

	// Initialize token cache with both token getters
	devLicenseTokenCache := tokencache.New(
		time.Hour,    // Default expiration
		time.Hour*24, // Cleanup interval
		dexClient,
	)

	// Setup token exchange client with token cache
	tokenExchangeClient, err := tokenexchange.NewClient(settings, devLicenseTokenCache, httpClient, logger.With().Str("component", "tokenexchange").Logger())
	if err != nil {
		return nil, err
	}

	// Recreate the tokenCache with both token getters properly set
	vehicleTokenCache := tokencache.New(
		time.Hour,    // Default expiration
		time.Hour*24, // Cleanup interval
		tokenExchangeClient,
	)

	// Setup telemetry client with token cache for vehicle tokens
	telemetryClient, err := telemetry.NewClient(settings.TelemetryAPIURL, httpClient, vehicleTokenCache)
	if err != nil {
		return nil, err
	}

	// Create controller with all required clients
	return NewController(settings, logger, identClient, telemetryClient, privateKey, getCert)
}
