package tmp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/mdlayher/vsock"
	"github.com/rs/zerolog"
)

const defaultHostCID = 3

var emptyConfig tls.Config

func defaultConfig() *tls.Config {
	return &emptyConfig
}

// NewHTTPClient creates a new HTTP client that tunnels connections to the enclave Host on the given port.
func NewHTTPClient(port uint32, tlsConfig *tls.Config, logger *zerolog.Logger) *http.Client {
	if tlsConfig == nil {
		tlsConfig = defaultConfig()
	}
	client := &http.Client{}
	client.Transport = &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			l := logger.With().Str("network", network).Str("addr", addr).Int("port", int(port)).Logger()
			l.Trace().Msg("DialContext")
			defer l.Trace().Msg("DialContext done")
			return dialVsock(port, network, addr, &l)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			l := logger.With().Str("network", network).Str("addr", addr).Int("port", int(port)).Logger()
			l.Trace().Msg("DialTLSContext")
			defer l.Trace().Msg("DialTLSContext done")
			vsockConn, err := dialVsock(port, network, addr, &l)
			if err != nil {
				return nil, fmt.Errorf("failed to dial vsock: %w", err)
			}
			config := modifiedConfig(addr, tlsConfig)
			tlsConn := tls.Client(vsockConn, config)
			l.Trace().Msg("Initiating TLS handshake")
			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				_ = vsockConn.Close()
				return nil, fmt.Errorf("failed TLS handshake: %w", err)
			}
			l.Trace().Msg("TLS handshake complete")
			return tlsConn, nil
		},
	}
	return client
}

// modifiedConfig modifies the TLS config to use the correct server name.
// copied from https://cs.opensource.google/go/go/+/refs/tags/go1.24.2:src/crypto/tls/tls.go;l=140-156
func modifiedConfig(addr string, config *tls.Config) *tls.Config {
	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}
	return config
}

func dialVsock(port uint32, network, addr string, logger *zerolog.Logger) (net.Conn, error) {
	logger.Trace().Msg("dialing vsock")
	defer logger.Trace().Msg("dialed vsock")
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
	vsockConn, err := vsock.Dial(defaultHostCID, port, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial vsock: %w", err)
	}
	_, err = vsockConn.Write([]byte(addr + "\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to write to vsock: %w", err)
	}
	return vsockConn, nil
}
