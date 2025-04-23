package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DIMO-Network/enclave-bridge/pkg/attest"
	"github.com/DIMO-Network/enclave-bridge/pkg/certs"
	"github.com/DIMO-Network/enclave-bridge/pkg/certs/acme"
	"github.com/DIMO-Network/enclave-bridge/pkg/client"
	"github.com/DIMO-Network/odometer-attester/internal/client/dex"
	"github.com/DIMO-Network/odometer-attester/internal/client/identity"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokenexchange"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog"
)

func CreateEnclaveWebServer(logger *zerolog.Logger, clientPort, challengePort uint32, settings *config.Settings) (*fiber.App, *tls.Config, error) {
	walletPrivateKey, certPrivateKey, err := GetKeys(settings, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get keys: %w", err)
	}

	// Setup HTTP client
	httpClient := client.NewHTTPClient(clientPort, nil)
	var certFunc certs.GetCertificateFunc
	var tlsConfig *tls.Config
	if settings.TLS.Enabled {
		tlsConfig, err = setupTLSConfig(settings, certPrivateKey, httpClient, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to setup TLS config: %w", err)
		}
		certFunc = tlsConfig.GetCertificate
	}

	// Setup the controller with all its dependencies
	ctrl, err := setupController(logger, settings, httpClient, walletPrivateKey, certFunc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup controller: %w", err)
	}

	app := createApp(logger, ctrl)

	err = registerKeys(context.Background(), logger, settings, httpClient, &walletPrivateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to register keys: %w", err)
	}
	return app, tlsConfig, nil
}

func createApp(logger *zerolog.Logger, ctrl *Controller) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, logger)
		},
		DisableStartupMessage: true,
	})

	app.Use(recover.New(recover.Config{
		Next:              nil,
		EnableStackTrace:  true,
		StackTraceHandler: nil,
	}))

	// Swagger documentation
	app.Get("/swagger/*", swagger.HandlerDefault)

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
	return app
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

// setupTLSConfig configures TLS settings including certificate management
func setupTLSConfig(settings *config.Settings, certPrivateKey *ecdsa.PrivateKey, httpClient *http.Client, logger *zerolog.Logger) (*tls.Config, error) {
	if settings.TLS.LocalCerts.CertFile != "" && settings.TLS.LocalCerts.KeyFile != "" {
		certFunc, err := certs.GetCertificatesFromSettings(&settings.TLS.LocalCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificates from settings: %w", err)
		}
		return &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certFunc,
		}, nil
	}
	certLogger := logger.With().Str("component", "acme").Logger()
	// Configure our ACME cert manager and get a certificate using ACME!
	certService, err := acme.NewCertManager(&acme.CertManagerConfig{
		ACMEConfig: &settings.TLS.ACMEConfig,
		Key:        certPrivateKey,
		HTTPClient: httpClient,
		Logger:     &certLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME cert manager: %w", err)
	}

	err = certService.Start(context.TODO(), logger)
	if err != nil {
		logger.Err(err).Msg("failed to start ACME cert manager")
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certService.GetCertificate,
		NextProtos:     []string{"http/1.1", "acme-tls/1"},
	}, nil
}

type AddSignerRequest struct {
	SignerAddress       string `json:"signerAddress"`
	AttestationDocument []byte `json:"attestationDocument"`
}

func registerKeys(ctx context.Context, logger *zerolog.Logger, settings *config.Settings, httpClient *http.Client, publicKey *ecdsa.PublicKey) error {
	endpoint, err := url.JoinPath(settings.SignerRegistryURL, "add-signer")
	if err != nil {
		return fmt.Errorf("failed to join URL: %w", err)
	}

	attRequest := &request.Attestation{
		PublicKey: crypto.FromECDSAPub(publicKey),
	}
	document, _, err := attest.GetNSMAttestation(attRequest)
	if err != nil {
		return fmt.Errorf("failed to get NSM attestation: %w", err)
	}
	signerRequest := AddSignerRequest{
		SignerAddress:       crypto.PubkeyToAddress(*publicKey).Hex(),
		AttestationDocument: document,
	}
	reqData, err := json.Marshal(signerRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal signer request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(reqData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to register keys: %s", string(body))
	}

	return nil
}
