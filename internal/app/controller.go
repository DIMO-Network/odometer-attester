package app

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/enclave-bridge/pkg/attest"
	"github.com/DIMO-Network/odometer-attester/internal/client/identity"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/hf/nitrite"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog"
	"github.com/segmentio/ksuid"
)

const (
	attestationVersion = "odometer-attestation/v0.0.1"
)

type Controller struct {
	identityClient         *identity.Client
	telemetryClient        *telemetry.Client
	logger                 *zerolog.Logger
	publicKey              *ecdsa.PublicKey
	nsmResult              *nitrite.Result
	vehicleContractAddress common.Address
	chainID                uint64
	devLicense             string
	privateKey             *ecdsa.PrivateKey
	lastCert               *tls.Certificate
	getCertFunc            func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func NewController(
	settings *config.Settings,
	logger *zerolog.Logger,
	identityClient *identity.Client,
	telemetryClient *telemetry.Client,
	privateKey *ecdsa.PrivateKey,
	getCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) (*Controller, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}
	return &Controller{
		identityClient:  identityClient,
		telemetryClient: telemetryClient,
		logger:          logger,
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		devLicense:      settings.DeveloperLicense,
		getCertFunc:     getCertFunc,
	}, nil
}

// GetVehicleInfo godoc
// @Summary Get vehicle information
// @Description Get information about a specific vehicle by token ID
// @Tags vehicle
// @Accept json
// @Produce json
// @Param tokenId path string true "Vehicle Token ID"
// @Success 200 {object} identity.GraphQLResponse
// @Failure 400 {object} codeResp
// @Failure 500 {object} codeResp
// @Router /vehicle/{tokenId} [get]
func (c *Controller) GetVehicleInfo(ctx *fiber.Ctx) error {
	vehicleTokenID := ctx.Params("tokenId")
	vehicleTokenIDUint, err := strconv.ParseUint(vehicleTokenID, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid vehicle token Id")
	}

	vehicleInfo, err := c.identityClient.GetVehicleInfo(ctx.Context(), uint32(vehicleTokenIDUint))
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to get vehicle info")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get vehicle info")
	}

	return ctx.JSON(vehicleInfo)
}

// GetOdometer godoc
// @Summary Get vehicle odometer reading
// @Description Get the odometer reading for a specific vehicle by token ID
// @Tags vehicle
// @Accept json
// @Produce json
// @Param tokenId path string true "Vehicle Token ID"
// @Success 200 {object} cloudevent.CloudEvent[json.RawMessage]
// @Failure 400 {object} codeResp
// @Failure 500 {object} codeResp
// @Router /vehicle/{tokenId}/odometer [get]
func (c *Controller) GetOdometer(ctx *fiber.Ctx) error {
	vehicleTokenID := ctx.Params("tokenId")
	vehicleTokenIDUint, err := strconv.ParseUint(vehicleTokenID, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid vehicle token Id")
	}

	odometer, err := c.telemetryClient.GetOdometer(ctx.Context(), uint32(vehicleTokenIDUint))
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to get odometer")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get odometer")
	}
	attestation, err := c.createAttestation(uint32(vehicleTokenIDUint), odometer.PowertrainTransmissionTravelledDistance.Value)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to create attestation")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create attestation")
	}

	return ctx.JSON(attestation)
}

// GetNSMAttestations godoc
// @Summary Get NSM attestation
// @Description Get the Nitro Security Module attestation
// @Tags attestation
// @Accept json
// @Produce json
// @Success 200 {object} nitrite.Result
// @Failure 500 {object} codeResp
// @Router /.well-known/nsm-attestation [get]
func (c *Controller) GetNSMAttestations(ctx *fiber.Ctx) error {
	certBytes, err := c.getCert(nil)

	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to marshal certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to marshal certificate")
	}
	req := &request.Attestation{
		PublicKey: crypto.FromECDSAPub(c.publicKey),
		UserData:  certBytes,
	}
	c.nsmResult, err = attest.GetNSMAttestation(req)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to get NSM attestation")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get NSM attestation")
	}
	return ctx.JSON(c.nsmResult)
}

type KeysResponse struct {
	PublicKey       string `json:"publicKey"`
	EthereumAddress string `json:"ethereumAddress"`
}

// GetKeys godoc
// @Summary Get public keys
// @Description Get the public key and Ethereum address of the controller
// @Tags keys
// @Accept json
// @Produce json
// @Success 200 {object} KeysResponse
// @Router /keys [get]
func (c *Controller) GetKeys(ctx *fiber.Ctx) error {
	keyResponse := KeysResponse{
		PublicKey:       "0x" + hex.EncodeToString(crypto.FromECDSAPub(c.publicKey)),
		EthereumAddress: crypto.PubkeyToAddress(*c.publicKey).Hex(),
	}
	return ctx.JSON(keyResponse)
}

func (c *Controller) GetUnsafeKeys(ctx *fiber.Ctx) error {
	return ctx.JSON(c.nsmResult)
}

func (c *Controller) getCert(hello *tls.ClientHelloInfo) ([]byte, error) {
	if c.getCertFunc == nil {
		// No certificate function configured, return nil
		return nil, nil
	}
	cert, err := c.getCertFunc(hello)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to get certificate")
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to get certificate")
	}

	// If the certificate is the same and the not after date is in the future, return the cached result
	if c.lastCert == cert {
		if cert == nil {
			return nil, nil
		}
		if c.nsmResult.Certificates[0].NotAfter.After(time.Now()) {
			return x509.MarshalPKIXPublicKey(cert.Certificate[0])
		}
	}

	c.lastCert = cert
	certBytes, err := x509.MarshalPKIXPublicKey(cert.Certificate[0])
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to marshal certificate")
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to marshal certificate")
	}
	return certBytes, nil
}

func (c *Controller) createAttestation(tokenID uint32, odometer float64) (*cloudevent.CloudEvent[json.RawMessage], error) {
	vehicleDID := cloudevent.NFTDID{
		ContractAddress: c.vehicleContractAddress,
		ChainID:         c.chainID,
		TokenID:         tokenID,
	}.String()
	odometerAttestation := odometerAttestation{
		Source:     c.devLicense,
		Subject:    vehicleDID,
		Producer:   crypto.PubkeyToAddress(*c.publicKey).Hex(),
		Time:       time.Now().UTC(),
		Odometer:   odometer,
		VehicleDID: vehicleDID,
		PCRs:       c.nsmResult.Document.PCRs,
	}
	attBytes, err := json.Marshal(odometerAttestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %w", err)
	}
	signature, err := signMessage(string(attBytes), c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	event := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion:     "1.0",
			Time:            time.Now().UTC(),
			ID:              ksuid.New().String(),
			Type:            cloudevent.TypeAttestation,
			Source:          c.devLicense,
			Subject:         vehicleDID,
			Producer:        crypto.PubkeyToAddress(*c.publicKey).Hex(),
			DataContentType: "application/json",
			DataVersion:     attestationVersion,
			Extras: map[string]any{
				"signature": signature,
			},
		},
		Data: json.RawMessage(attBytes),
	}
	return &event, nil
}

type odometerAttestation struct {
	Source     string          `json:"source"`
	Subject    string          `json:"subject"`
	Producer   string          `json:"producer"`
	Time       time.Time       `json:"time"`
	Odometer   float64         `json:"odometer"`
	VehicleDID string          `json:"vehicleDID"`
	PCRs       map[uint][]byte `json:"pcrs"`
}

// signMessage signs the message with the configured private key.
func signMessage(message string, privateKey *ecdsa.PrivateKey) (string, error) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	sign := crypto.Keccak256Hash([]byte(msg))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)
	if err != nil {
		return "", err
	}

	signature[64] += 27 // Support old Ethereum format
	return "0x" + hex.EncodeToString(signature), nil
}
