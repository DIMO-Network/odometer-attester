package app

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DIMO-Network/enclave-bridge/pkg/attest"
	"github.com/DIMO-Network/enclave-bridge/pkg/client"
	"github.com/DIMO-Network/odometer-attester/internal/client/dex"
	"github.com/DIMO-Network/odometer-attester/internal/client/identity"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokenexchange"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/hf/nitrite"
	"github.com/rs/zerolog"
)

// setupController creates and configures all the clients needed for the controller
func setupController(logger *zerolog.Logger, settings *config.Settings, clientPort uint32, privateKey *ecdsa.PrivateKey, attestResults *nitrite.Result) (*Controller, error) {
	// Setup HTTP client
	httpClient := client.NewHTTPClient(clientPort)

	// Setup identity client
	identClient, err := identity.NewClient(settings.IdentityAPIURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity client: %w", err)
	}

	// Setup dex client for developer license tokens
	dexClient, err := dex.NewClient(settings, privateKey, httpClient)
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
	tokenExchangeClient, err := tokenexchange.NewClient(settings, devLicenseTokenCache, httpClient)
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
	return NewController(identClient, telemetryClient, logger, &privateKey.PublicKey, attestResults)
}

// CreateEnclaveWebServer creates a new web server with the given logger and settings.
func CreateEnclaveWebServer(logger *zerolog.Logger, port uint32, settings *config.Settings) (*fiber.App, error) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, logger)
		},
		DisableStartupMessage: true,
	})
	privateKey, attestResults, err := attest.GetNSMAttestationAndKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get NSM attestation and key: %w", err)
	}

	// Setup the controller with all its dependencies
	ctrl, err := setupController(logger, settings, port, privateKey, attestResults)
	if err != nil {
		return nil, err
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
	app.Get("/vehicle/:tokenId", ctrl.GetVehicleInfo)
	app.Get("/vehicle/:tokenId/odometer", ctrl.GetOdometer)
	app.Get("/nsm-attestations", ctrl.GetNSMAttestations)
	app.Get("/keys", ctrl.GetKeys)
	return app, nil
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
