package app

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/odometer-attester/internal/client/telemetry"
	"github.com/DIMO-Network/odometer-attester/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/segmentio/ksuid"
)

const (
	attestationVersion = "odometer-attestation/v0.0.1"
)

type Controller struct {
	telemetryClient        *telemetry.Client
	logger                 *zerolog.Logger
	publicKey              *ecdsa.PublicKey
	PCRs                   map[uint][]byte
	vehicleContractAddress common.Address
	chainID                uint64
	devLicense             string
	privateKey             *ecdsa.PrivateKey
	getCertFunc            func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func NewController(
	settings *config.Settings,
	logger *zerolog.Logger,
	telemetryClient *telemetry.Client,
	privateKey *ecdsa.PrivateKey,
	getCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) (*Controller, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}
	// TODO: Need PCR values
	return &Controller{
		telemetryClient: telemetryClient,
		logger:          logger,
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		devLicense:      settings.DeveloperLicense,
		getCertFunc:     getCertFunc,
	}, nil
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
// @Router /vehicle/odometer/{tokenId} [get]
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
		PCRs: pcrValues{
			PCR0: c.PCRs[0],
			PCR1: c.PCRs[1],
			PCR2: c.PCRs[2],
		},
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
	Source     string    `json:"source"`
	Subject    string    `json:"subject"`
	Producer   string    `json:"producer"`
	Time       time.Time `json:"time"`
	Odometer   float64   `json:"odometer"`
	VehicleDID string    `json:"vehicleDID"`
	PCRs       pcrValues `json:"pcrMeasurements"`
}

// pcrValues contains the values for the PCR0, PCR1, and PCR2.
type pcrValues struct {
	PCR0 hexutil.Bytes `json:"pcr0"`
	PCR1 hexutil.Bytes `json:"pcr1"`
	PCR2 hexutil.Bytes `json:"pcr2"`
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
