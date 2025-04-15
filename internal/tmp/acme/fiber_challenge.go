package acme

import (
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// HTTP01Provider is a simple store for HTTP-01 challenges.
type HTTP01Provider struct {
	challenges map[string]string
	mu         sync.RWMutex
	logger     *zerolog.Logger
}

// NewHTTP01Provider creates a new HTTP01 provider.
func NewHTTP01Provider(logger *zerolog.Logger) *HTTP01Provider {
	if logger == nil {
		l := zerolog.Nop()
		logger = &l
	}
	return &HTTP01Provider{
		challenges: make(map[string]string),
		logger:     logger,
	}
}

// Present implements challenge.Provider interface
// Adds challenge data to be validated by the CA
func (p *HTTP01Provider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	p.challenges[token] = keyAuth
	p.mu.Unlock()

	p.logger.Debug().
		Str("domain", domain).
		Str("token", token).
		Msg("Stored new ACME challenge")

	return nil
}

// CleanUp implements challenge.Provider interface
// Removes the challenge once it's no longer needed.
func (p *HTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	delete(p.challenges, token)
	p.mu.Unlock()

	p.logger.Debug().
		Str("domain", domain).
		Str("token", token).
		Msg("Cleaned up ACME challenge")

	return nil
}

// GetChallenge retrieves a challenge by token.
func (p *HTTP01Provider) GetChallenge(token string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	keyAuth, exists := p.challenges[token]

	if exists {
		p.logger.Debug().
			Str("token", token).
			Msg("Retrieved ACME challenge")
	} else {
		p.logger.Debug().
			Str("token", token).
			Msg("ACME challenge not found")
	}

	return keyAuth, exists
}

// SetupFiberHandler sets up the ACME challenge handler for a Fiber app.
func SetupFiberHandler(app *fiber.App, provider *HTTP01Provider) {
	app.Get("/.well-known/acme-challenge/:token", func(c *fiber.Ctx) error {
		token := c.Params("token")

		keyAuth, exists := provider.GetChallenge(token)
		if !exists {
			return c.SendStatus(fiber.StatusNotFound)
		}

		c.Set("Content-Type", "text/plain")
		return c.SendString(keyAuth)
	})
}
