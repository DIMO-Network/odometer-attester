package acme

import (
	"crypto/tls"
	"sync"

	"github.com/go-acme/lego/challenge/tlsalpn01"
	"github.com/rs/zerolog"
)

// TLSALPN01Provider is a simple store for TLS-ALPN-01 challenges.
type TLSALPN01Provider struct {
	challenges map[string]*tls.Certificate
	mu         sync.RWMutex
	logger     *zerolog.Logger
}

// NewTLSALPN01Provider creates a new TLSALPN01 provider.
func NewTLSALPN01Provider(logger *zerolog.Logger) *TLSALPN01Provider {
	if logger == nil {
		l := zerolog.Nop()
		logger = &l
	}
	return &TLSALPN01Provider{
		logger:     logger,
		challenges: make(map[string]*tls.Certificate),
	}
}

// Present implements challenge.Provider interface.
// Adds challenge data to be validated by the CA.
func (p *TLSALPN01Provider) Present(domain, token, keyAuth string) error {
	// Generate the challenge certificate using the provided keyAuth and domain.
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.challenges[token] = cert
	p.mu.Unlock()

	p.logger.Debug().
		Str("domain", domain).
		Str("token", token).
		Msg("Stored new TLS-ALPN-01 challenge")

	return nil
}

// CleanUp implements challenge.Provider interface
// Removes the challenge once it's no longer needed.
func (p *TLSALPN01Provider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	delete(p.challenges, token)
	p.mu.Unlock()
	p.logger.Debug().
		Str("domain", domain).
		Str("token", token).
		Msg("Cleaned up TLS-ALPN-01 challenge")

	return nil
}

// GetChallenge retrieves a challenge by token.
func (p *TLSALPN01Provider) GetChallenge(token string) (*tls.Certificate, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cert, ok := p.challenges[token]
	if ok {
		p.logger.Debug().
			Str("token", token).
			Msg("Retrieved TLS-ALPN-01 challenge")
	} else {
		p.logger.Debug().
			Str("token", token).
			Msg("TLS-ALPN-01 challenge not found")
	}

	return cert, ok
}
