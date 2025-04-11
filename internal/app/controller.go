package app

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/odometer-attester/internal/client/identity"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/hf/nitrite"
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
}

func NewController(
	identityClient *identity.Client,
	telemetryClient *telemetry.Client,
	logger *zerolog.Logger,
	privateKey *ecdsa.PrivateKey,
	nsmResult *nitrite.Result,
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
	attestation, err := c.createAttestation(uint32(vehicleTokenIDUint), odometer.PowertrainTransmissionTravelledDistance.Value)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to create attestation")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create attestation")
	}

	return ctx.JSON(attestation)
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

func (c *Controller) GetUnsafeKeys(ctx *fiber.Ctx) error {
	return ctx.JSON(c.nsmResult)
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
