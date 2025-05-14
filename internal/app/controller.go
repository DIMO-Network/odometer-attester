package app

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/odometer-attester/internal/client/dis"
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
	publicKey              *ecdsa.PublicKey
	pcrs                   map[uint][]byte
	vehicleContractAddress common.Address
	chainID                uint64
	devLicense             string
	privateKey             *ecdsa.PrivateKey
	getCertFunc            func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	disClient              *dis.Client
}

func NewController(
	settings *config.Settings,
	telemetryClient *telemetry.Client,
	disClient *dis.Client,
	privateKey *ecdsa.PrivateKey,
	getCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	pcrs map[uint][]byte,
) (*Controller, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}
	if pcrs == nil {
		return nil, errors.New("pcrs are nil")
	}
	if pcrs[0] == nil || pcrs[1] == nil || pcrs[2] == nil {
		return nil, errors.New("pcrs are nil")
	}
	if disClient == nil {
		return nil, errors.New("dis client is nil")
	}
	if telemetryClient == nil {
		return nil, errors.New("telemetry client is nil")
	}

	return &Controller{
		telemetryClient:        telemetryClient,
		disClient:              disClient,
		privateKey:             privateKey,
		publicKey:              &privateKey.PublicKey,
		devLicense:             settings.DeveloperLicense,
		getCertFunc:            getCertFunc,
		pcrs:                   pcrs,
		vehicleContractAddress: settings.VehicleNFTContractAddress,
		chainID:                settings.ChainID,
	}, nil
}

// GetOdometer godoc
// @Summary Get vehicle odometer reading
// @Description Get the odometer reading for a specific vehicle by token ID
// @Tags vehicle
// @Accept json
// @Produce json
// @Param tokenId path string true "Vehicle Token ID"
// @Param upload query string false "Upload attestation DIS"
// @Param isPersonal query string false "Is personal attestation"
// @Success 200 {object} cloudevent.CloudEvent[json.RawMessage]
// @Failure 400 {object} codeResp
// @Failure 500 {object} codeResp
// @Router /vehicle/odometer/{tokenId} [get]
func (c *Controller) GetOdometer(ctx *fiber.Ctx) error {
	logger := zerolog.Ctx(ctx.UserContext()).With().Str("component", "GetOdometer").Logger()
	vehicleTokenID := ctx.Params("tokenId")
	vehicleTokenIDUint, ok := new(big.Int).SetString(vehicleTokenID, 10)
	if !ok {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid vehicle token Id")
	}

	uploadQuery := ctx.Query("upload")
	upload := strings.EqualFold(uploadQuery, "true")

	isPersonalQuery := ctx.Query("isPersonal")
	isPersonal := strings.EqualFold(isPersonalQuery, "true")

	odometer, err := c.telemetryClient.GetOdometer(ctx.Context(), vehicleTokenIDUint)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get odometer")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get odometer")
	}
	attEvent, err := c.createAttestation(vehicleTokenIDUint, odometer.PowertrainTransmissionTravelledDistance.Value, isPersonal)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create attestation")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create attestation")
	}
	if upload {
		attBytes, err := json.Marshal(attEvent)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to marshal attestation")
		}
		err = c.disClient.UploadAttestation(logger.WithContext(ctx.Context()), attBytes)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to upload attestation")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to upload attestation")
		}
	}
	return ctx.JSON(attEvent)
}

func (c *Controller) createAttestation(tokenID *big.Int, odometer float64, isPersonal bool) (*cloudevent.CloudEvent[json.RawMessage], error) {
	vehicleDID := cloudevent.ERC721DID{
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
			PCR0: c.pcrs[0],
			PCR1: c.pcrs[1],
			PCR2: c.pcrs[2],
		},
	}
	attBytes, err := json.Marshal(odometerAttestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %w", err)
	}
	signature, err := signMessage(string(attBytes), c.privateKey, isPersonal)
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
func signMessage(message string, privateKey *ecdsa.PrivateKey, isPersonal bool) (string, error) {
	msg := message
	if isPersonal {
		msg = fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	}
	sign := crypto.Keccak256Hash([]byte(msg))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)
	if err != nil {
		return "", err
	}

	signature[64] += 27 // Support old Ethereum format
	return "0x" + hex.EncodeToString(signature), nil
}
