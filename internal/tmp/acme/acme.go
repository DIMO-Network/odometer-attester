package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/gofiber/fiber/v2"
	"github.com/mdlayher/vsock"
	"golang.org/x/sync/errgroup"

	"github.com/rs/zerolog"
)

const (
	// acmeDirectoryURL The ACME directory URL for your ACME server
	acmeDirectoryURL = "https://example.org/acme/acme/directory"

	// tickFrequency how frequently we should check whether our cert needs renewal
	tickFrequency = 15 * time.Second
)

// LegoUser implements registration.User, required by lego.
type LegoUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

// GetEmail returns the email address of the user.
func (l *LegoUser) GetEmail() string {
	return l.email
}

// GetRegistration returns the registration resource for the user.
func (l *LegoUser) GetRegistration() *registration.Resource {
	return l.registration
}

// GetPrivateKey returns the private key for the user.
func (l *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return l.key
}

// SupportsCurve returns the key type and true if the curve is supported.
func SupportsCurve(curve elliptic.Curve) (certcrypto.KeyType, bool) {
	switch curve {
	case elliptic.P256():
		return certcrypto.EC256, true
	case elliptic.P384():
		return certcrypto.EC384, true
	}
	return "", false
}

// Uses techniques from https://diogomonica.com/2017/01/11/hitless-tls-certificate-rotation-in-go/
// to automatically rotate certificates when they're renewed.

// CertManager manages ACME certificate and renewal.
type CertManager struct {
	acmeClient  *lego.Client
	resource    *certificate.Resource
	certificate *tls.Certificate
	leaf        *x509.Certificate
	domains     []string
	vsockPort   uint32
	app         *fiber.App
	sync.RWMutex
}

// CertManagerConfig contains configuration options for creating a new ACMECertManager.
type CertManagerConfig struct {
	Key             *ecdsa.PrivateKey
	HTTPClient      *http.Client
	Logger          *zerolog.Logger
	Email           string
	CADirURL        string
	Domains         []string
	VsockListenPort uint32
}

// NewCertManager configures an ACME client, creates & registers a new ACME
// user. After creating a client you must call ObtainCertificate and
// RenewCertificate yourself.
func NewCertManager(acmeConfig CertManagerConfig) (*CertManager, error) {
	user := &LegoUser{
		email: acmeConfig.Email,
		key:   acmeConfig.Key,
	}

	keyType, ok := SupportsCurve(acmeConfig.Key.PublicKey.Curve)
	if !ok {
		return nil, fmt.Errorf("unsupported curve: %s", acmeConfig.Key.Curve)
	}

	// Create a configuration using our HTTPS client, ACME server, user details.
	config := &lego.Config{
		CADirURL:   acmeConfig.CADirURL,
		User:       user,
		HTTPClient: acmeConfig.HTTPClient,
		Certificate: lego.CertificateConfig{
			KeyType: keyType,
			Timeout: 30 * time.Second,
		},
	}

	// Create an ACME client and configure use of `http-01` challenge
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	provider := NewHTTP01Provider(acmeConfig.Logger)

	app := fiber.New()
	SetupFiberHandler(app, provider)
	err = client.Challenge.SetHTTP01Provider(provider)
	if err != nil {
		return nil, fmt.Errorf("couldn't set HTTP-01 provider: %w", err)
	}

	// Register our ACME user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("couldn't register ACME user: %w", err)
	}
	user.registration = reg

	return &CertManager{
		acmeClient: client,
		domains:    acmeConfig.Domains,
		vsockPort:  acmeConfig.VsockListenPort,
		app:        app,
	}, nil
}

// Start obtains a certificate and starts a renewal ticker.
func (c *CertManager) Start(ctx context.Context, logger *zerolog.Logger) error {
	// Create a listener for the enclave challenge server.
	challengeListener, err := vsock.Listen(c.vsockPort, nil)
	if err != nil {
		return fmt.Errorf("couldn't listen on vsock port %d: %w", c.vsockPort, err)
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return c.app.Listener(challengeListener)
	})
	group.Go(func() error {
		<-groupCtx.Done()
		err := c.app.Shutdown()
		if err != nil {
			return fmt.Errorf("error shutting down ACME: %w", err)
		}
		return challengeListener.Close()
	})
	group.Go(func() error {
		c.runRenewal(ctx, logger)
		return nil
	})
	err = group.Wait()
	if err != nil {
		return fmt.Errorf("error starting ACME: %w", err)
	}
	return nil
}

// ObtainCertificate gets a new certificate using ACME. Not thread safe.
func (c *CertManager) ObtainCertificate() error {
	request := certificate.ObtainRequest{
		Domains: c.domains,
		Bundle:  true,
	}

	resource, err := c.acmeClient.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	return c.switchCertificate(resource)
}

// RenewCertificate renews an existing certificate using ACME. Not thread safe.
func (c *CertManager) RenewCertificate() error {
	resource, err := c.acmeClient.Certificate.RenewWithOptions(*c.resource, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return err
	}

	return c.switchCertificate(resource)
}

// GetCertificate locks around returning a tls.Certificate; use as tls.Config.GetCertificate.
func (c *CertManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.RLock()
	defer c.RUnlock()
	return c.certificate, nil
}

// GetLeaf returns the currently valid leaf x509.Certificate.
func (c *CertManager) GetLeaf() x509.Certificate {
	c.RLock()
	defer c.RUnlock()
	return *c.leaf
}

// NextRenewal returns when the certificate will be 2/3 of the way to expiration.
func (c *CertManager) NextRenewal() time.Time {
	leaf := c.GetLeaf()
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore).Seconds()
	return leaf.NotBefore.Add(time.Duration(lifetime*2/3) * time.Second)
}

// NeedsRenewal returns true if the certificate's age is more than 2/3 it's
// lifetime.
func (c *CertManager) NeedsRenewal() bool {
	return time.Now().After(c.NextRenewal())
}

func (c *CertManager) switchCertificate(newResource *certificate.Resource) error {
	// The certificate.Resource represents our certificate as a PEM-encoded
	// bundle of bytes. Let's process it. First create a tls.Certificate
	// for use with the tls package.
	crt, err := tls.X509KeyPair(newResource.Certificate, newResource.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create tls.Certificate: %w", err)
	}

	// Now create a x509.Certificate so we can figure out when the cert
	// expires. Note that the first certificate in the bundle is the leaf.
	// Go ahead and set crt.Leaf as an optimization.
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	crt.Leaf = leaf

	c.Lock()
	defer c.Unlock()
	c.resource = newResource
	c.certificate = &crt
	c.leaf = leaf

	return nil
}

// runRenewal schedules periodic certificate renewals
// We tick every timeFrequency but only renew if the certificate
// is approaching expiration. That'll give us some resilience to CA
// downtime.
func (c *CertManager) runRenewal(ctx context.Context, logger *zerolog.Logger) {
	ticker := time.NewTicker(tickFrequency)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.NeedsRenewal() {
				logger.Info().Msg("Renewing certificate")
				err := c.RenewCertificate()
				if err != nil {
					logger.Error().Err(err).Msg("Error loading certificate and key")
				} else {
					leaf := c.GetLeaf()
					logger.Info().Msgf("Renewed certificate: %s [%s - %s]", leaf.Subject, leaf.NotBefore, leaf.NotAfter)
					logger.Info().Msgf("Next renewal at %s (%s)", c.NextRenewal(), c.NextRenewal().Sub(time.Now()))
				}
			}
		}
	}
}
