package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	// import docs for swagger generation.
	bridgecfg "github.com/DIMO-Network/enclave-bridge/pkg/config"
	"github.com/DIMO-Network/enclave-bridge/pkg/enclave"
	"github.com/DIMO-Network/enclave-bridge/pkg/enclave/handshake"
	"github.com/DIMO-Network/enclave-bridge/pkg/watchdog"
	_ "github.com/DIMO-Network/odometer-attester/docs"
	"github.com/DIMO-Network/odometer-attester/internal/app"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/mdlayher/vsock"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// @title Odometer Attester API
// @version 1.0
// @description This is the API documentation for the Odometer Attester service
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
const (
	// heartInterval is the interval to check if the enclave is still alive.
	heartInterval = 10 * time.Second
	appName       = "odometer-attester"
)

const (
	serverTunnelPort uint32 = iota + 5001
	clientTunnelPort
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	group, gCtx := errgroup.WithContext(ctx)
	// Create a logger that can be used to log messages to the enclave-bridge.
	logger, cleanup, err := enclave.GetAndSetDefaultLoggerWithSocket(appName, enclave.StdoutPort)
	if err != nil {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
		logger.Fatal().Err(err).Msg("Failed to create logger socket.")
	}
	defer cleanup()

	go func() {
		<-ctx.Done()
		logger.Info().Msg("Received signal in enclave, shutting down...")
	}()

	logger.Debug().Msg("Starting enclave app")
	cid, err := vsock.ContextID()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to get context ID.")
	}
	var bridgeSetup handshake.BridgeHandshake
	err = bridgeSetup.StartHandshake(ctx)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to setup bridge.")
	}
	settings, err := handshake.ConfigFromEnvMap[config.Settings](bridgeSetup.Environment())
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to parse environment variables.")
	}

	err = enclave.SetLoggerLevel(settings.LogLevel)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to set logger level.")
	}

	bridgeSettings := bridgecfg.BridgeSettings{
		AppName: appName,
		Logger: bridgecfg.LoggerSettings{
			Level: settings.LogLevel,
		},
		Servers: []bridgecfg.ServerSettings{
			{
				EnclaveCID:        cid,
				EnclaveListenPort: serverTunnelPort,
				BridgeTCPPort:     uint32(settings.Port),
			},
		},
		Clients: []bridgecfg.ClientSettings{
			{
				EnclaveDialPort: clientTunnelPort,
				RequestTimeout:  time.Minute * 5,
			},
		},
		Watchdog: watchdog.NewStandardSettings(),
	}

	runHandshake(ctx, &bridgeSetup, &bridgeSettings, group)

	// Wait for the bridge to be setup.
	logger.Debug().Msg("Waiting for bridge setup")
	err = bridgeSetup.WaitForBridgeSetup()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to setup bridge.")
	}

	// Create a listener for the enclave web server.
	listener, err := vsock.Listen(serverTunnelPort, nil)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Couldn't listen on port %d.", serverTunnelPort)
	}
	logger.Info().Msgf("Listening on %s", listener.Addr())

	// Create the enclave server using the new listener and logger
	enclaveApp, tlsConfig, err := app.CreateEnclaveWebServer(&logger, clientTunnelPort, &settings)
	if err != nil {
		_ = listener.Close()
		_ = bridgeSetup.Close()
		logger.Fatal().Err(err).Msg("Couldn't create enclave web server.")
	}
	_ = bridgeSetup.Close()

	RunFiberWithListener(gCtx, enclaveApp, listener, tlsConfig, group)

	err = group.Wait()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to run servers.")
	}
}

// runHandshake runs the handshake and returns a context that can be used to stop the handshake.
func runHandshake(ctx context.Context, bridgeSetup *handshake.BridgeHandshake, bridgeSettings *bridgecfg.BridgeSettings, group *errgroup.Group) {
	group.Go(func() error {
		err := bridgeSetup.FinishHandshakeAndWait(ctx, bridgeSettings)
		if err != nil {
			return fmt.Errorf("failed to run handshake: %w", err)
		}
		return nil
	})
}

// RunFiberWithListener runs a fiber server with a listener and returns a context that can be used to stop the server.
func RunFiberWithListener(ctx context.Context, fiberApp *fiber.App, listener net.Listener, tlsConfig *tls.Config, group *errgroup.Group) {
	group.Go(func() error {
		if tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
		if err := fiberApp.Listener(listener); err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		<-ctx.Done()
		if err := fiberApp.Shutdown(); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		return nil
	})
}
