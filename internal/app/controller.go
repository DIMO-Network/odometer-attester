package app

import (
	"crypto/ecdsa"
	"encoding/hex"
	"strconv"

	"github.com/DIMO-Network/odometer-attester/internal/client/identity"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/hf/nitrite"
	"github.com/rs/zerolog"
)

type Controller struct {
	identityClient  *identity.Client
	telemetryClient *telemetry.Client
	logger          *zerolog.Logger
	publicKey       *ecdsa.PublicKey
	nsmResult       *nitrite.Result
}

func NewController(
	identityClient *identity.Client,
	telemetryClient *telemetry.Client,
	logger *zerolog.Logger,
	publicKey *ecdsa.PublicKey,
	nsmResult *nitrite.Result,
) (*Controller, error) {
	return &Controller{
		identityClient:  identityClient,
		telemetryClient: telemetryClient,
		logger:          logger,
		publicKey:       publicKey,
		nsmResult:       nsmResult,
	}, nil
}

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

	return ctx.JSON(odometer)
}

// GetNSMAttestations returns the NSM attestation.
func (c *Controller) GetNSMAttestations(ctx *fiber.Ctx) error {
	return ctx.JSON(c.nsmResult)
}

type KeysResponse struct {
	PublicKey       string `json:"publicKey"`
	EthereumAddress string `json:"ethereumAddress"`
}

// GetKeys returns the public key and ethereum address of the controller.
func (c *Controller) GetKeys(ctx *fiber.Ctx) error {
	keyResponse := KeysResponse{
		PublicKey:       "0x" + hex.EncodeToString(crypto.FromECDSAPub(c.publicKey)),
		EthereumAddress: crypto.PubkeyToAddress(*c.publicKey).Hex(),
	}
	return ctx.JSON(keyResponse)
}
