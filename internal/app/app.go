package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	"github.com/DIMO-Network/enclave-bridge/pkg/enclave"
	"github.com/DIMO-Network/enclave-bridge/pkg/wellknown"
	"github.com/DIMO-Network/odometer-attester/internal/client/dex"
	"github.com/DIMO-Network/odometer-attester/internal/client/dis"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokencache"
	"github.com/DIMO-Network/odometer-attester/internal/client/tokenexchange"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog"
)

func CreateEnclaveWebServer(logger *zerolog.Logger, clientPort uint32, settings *config.Settings) (*fiber.App, *tls.Config, error) {
	walletPrivateKey, certPrivateKey, err := enclave.CreateKeys()
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

	// Setup NSM controller
	wellKnownCtrl, err := wellknown.NewController(&walletPrivateKey.PublicKey, certFunc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup NSM controller: %w", err)
	}

	app := createApp(logger, ctrl, wellKnownCtrl)

	err = registerKeys(context.Background(), logger, settings, httpClient, &walletPrivateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return app, tlsConfig, nil
}

func createApp(logger *zerolog.Logger, ctrl *Controller, wellKnownCtrl *wellknown.Controller) *fiber.App {
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

	app.Use(func(c *fiber.Ctx) error {
		userCtx := logger.With().Str("httpPath", strings.TrimPrefix(c.Path(), "/")).
			Str("httpMethod", c.Method()).Logger().WithContext(c.UserContext())
		c.SetUserContext(userCtx)
		return c.Next()
	})

	// Swagger documentation
	app.Get("/swagger/*", swagger.HandlerDefault)

	app.Get("/", HealthCheck)
	wellknown.RegisterRoutes(app, wellKnownCtrl)
	app.Get("/vehicle/odometer/:tokenId", ctrl.GetOdometer)
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

// setupController creates and configures all the clients needed for the controller.
func setupController(logger *zerolog.Logger, settings *config.Settings, httpClient *http.Client, privateKey *ecdsa.PrivateKey, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*Controller, error) {
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

	// Setup token exchange client with token cache
	disClient, err := dis.NewClient(settings, devLicenseTokenCache, httpClient)
	if err != nil {
		return nil, err
	}

	// Create controller with all required clients
	return NewController(settings, telemetryClient, disClient, privateKey, getCert)
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
type AddSignerResponse struct {
	TxHash       string `json:"txHash"`
	AlreadyAdded bool   `json:"alreadyAdded"`
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

	var addSignerResponse AddSignerResponse
	err = json.NewDecoder(resp.Body).Decode(&addSignerResponse)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if addSignerResponse.AlreadyAdded {
		return nil
	}
	rpcClient, err := rpc.DialOptions(ctx, settings.EthereumRPCURL, rpc.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}
	client := ethclient.NewClient(rpcClient)
	txHash := common.HexToHash(addSignerResponse.TxHash)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	logger.Info().Str("txHash", txHash.Hex()).Msg("waiting for signer registration to be mined")
	_, err = WaitMined(ctx, client, txHash)
	if err != nil {
		return fmt.Errorf("failed to wait for transaction: %w", err)
	}
	return nil
}

// WaitMined waits for tx to be mined on the blockchain.
// It stops waiting when the context is canceled.
func WaitMined(ctx context.Context, b bind.DeployBackend, txHash common.Hash) (*types.Receipt, error) {
	queryTicker := time.NewTicker(time.Second * 5)
	defer queryTicker.Stop()

	for {
		receipt, err := b.TransactionReceipt(ctx, txHash)
		if err == nil {
			return receipt, nil
		}

		// Wait for the next round.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}
