// Package vinvc provides the controller for handling VIN VC-related requests.
package vinvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/erc191"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/segmentio/ksuid"
)

const (
	daysInWeek = 7
)

// Service handles VIN VC-related operations.
type Service struct {
	logger            *zerolog.Logger
	vcRepo            VCRepo
	identityAPI       IdentityAPI
	fingerprintRepo   FingerprintRepo
	vinAPI            VINAPI
	vehicleNFTAddress string
	chainID           uint64
	VINVCDataVersion  string
	privateKey        *ecdsa.PrivateKey
}

// NewService creates a new Service for VIN VC operations.
func NewService(
	logger *zerolog.Logger,
	vcRepo VCRepo,
	identityService IdentityAPI,
	fingerprintService FingerprintRepo,
	vinService VINAPI,
	settings *config.Settings,
	privateKey *ecdsa.PrivateKey,
) *Service {

	return &Service{
		logger:            logger,
		vcRepo:            vcRepo,
		identityAPI:       identityService,
		fingerprintRepo:   fingerprintService,
		vinAPI:            vinService,
		vehicleNFTAddress: settings.VehicleNFTAddress,
		chainID:           uint64(settings.DIMORegistryChainID),
		privateKey:        privateKey,
		VINVCDataVersion:  settings.VINDataVersion,
	}
}

// GenerateVINVC generates a new VIN VC and returns it.
func (v *Service) CreateVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error) {
	rawVC, err := v.createVINAttestation(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	return rawVC, nil
}

// GenerateVINVCAndStore generates a new VIN VC and stores it in Object Storage.
func (v *Service) CreateAndStoreVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error) {
	rawVC, err := v.createVINAttestation(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	err = v.vcRepo.UploadAttestation(ctx, rawVC)
	if err != nil {
		return nil, richerrors.Error{Err: err, ExternalMsg: "Failed to store VC"}
	}
	return rawVC, nil
}

func (v *Service) createVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error) {
	// get meta data about the vehilce
	vehicleDID := cloudevent.ERC721DID{
		ChainID:         v.chainID,
		ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
		TokenID:         big.NewInt(int64(tokenID)),
	}
	vehicleInfo, err := v.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return nil, richerrors.Error{Err: err, ExternalMsg: "Failed to get vehicle info"}
	}

	// get a valid VIN for the vehilce
	validFP, err := v.getValidFingerPrint(ctx, vehicleInfo, "")
	if err != nil {
		return nil, err
	}

	// creatae the subject for the VC
	vinSubject := types.VINSubject{
		VehicleDID:                  vehicleDID.String(),
		VehicleIdentificationNumber: validFP.VIN,
		VehicleTokenID:              tokenID,
		CountryCode:                 "",
		RecordedBy:                  validFP.Producer,
		RecordedAt:                  validFP.Time,
		VehicleContractAddress:      "eth:" + v.vehicleNFTAddress,
	}

	// create the new VC
	expTime := time.Now().AddDate(0, 0, daysInWeek-int(time.Now().Weekday())).UTC().Truncate(time.Hour * 24)
	rawVC, err := v.compileVINAttestation(vinSubject, expTime)
	if err != nil {
		return nil, richerrors.Error{Err: err, ExternalMsg: "Failed to create VC"}
	}

	return rawVC, nil
}

// getValidFingerPrint validates and reconciles VINs from the paired devices.
func (v *Service) getValidFingerPrint(ctx context.Context, vehicleInfo *models.VehicleInfo, countryCode string) (*models.DecodedFingerprintData, error) {
	if len(vehicleInfo.PairedDevices) == 0 {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No paired devices")
	}
	var latestFP *models.DecodedFingerprintData

	var fingerprintErr error
	for _, device := range vehicleInfo.PairedDevices {
		fingerprint, err := v.fingerprintRepo.GetLatestFingerprintMessages(ctx, vehicleInfo.DID, device)
		if err != nil {
			var richErr richerrors.Error
			if !errors.As(err, &richErr) {
				// log the error and continue to the next device if possible
				msg := fmt.Sprintf("Failed to get latest vin message for device %s", device.DID.String())
				err = richerrors.Error{Err: err, ExternalMsg: msg}
			}
			fingerprintErr = errors.Join(fingerprintErr, err)
			continue
		}

		if latestFP == nil || latestFP.VIN == "" || fingerprint.Time.After(latestFP.Time) {
			latestFP = fingerprint
		}
	}

	// return error to the user if no VINs were found
	if (latestFP == nil || latestFP.VIN == "") && fingerprintErr != nil {
		return nil, fingerprintErr
	}
	decodedNameSlug, err := v.vinAPI.DecodeVIN(ctx, latestFP.VIN, countryCode)
	if err != nil {
		return nil, richerrors.Error{Err: err, ExternalMsg: "Server failed to decode VIN"}
	}
	if decodedNameSlug != vehicleInfo.NameSlug {
		message := fmt.Sprintf("Invalid VIN Decoding expected: %s got: %s", vehicleInfo.NameSlug, decodedNameSlug)
		err := fmt.Errorf("decodedNameSlug: %s != identityNameSlug: %s vin = %s", decodedNameSlug, vehicleInfo.NameSlug, latestFP.VIN)
		return nil, richerrors.Error{Err: err, ExternalMsg: message, Code: fiber.StatusBadRequest}
	}

	return latestFP, nil
}

func (v *Service) CreateManualVINAttestation(ctx context.Context, tokenID uint32, vin string, countryCode string) (*cloudevent.RawEvent, error) {
	producer := cloudevent.EthrDID{
		ChainID:         v.chainID,
		ContractAddress: sources.DINCSource,
	}.String()

	// create the subject for the Manually created VC
	vinSubject := types.VINSubject{
		VehicleDID: cloudevent.ERC721DID{
			ChainID:         v.chainID,
			ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
			TokenID:         big.NewInt(int64(tokenID)),
		}.String(),
		VehicleIdentificationNumber: vin,
		VehicleTokenID:              tokenID,
		CountryCode:                 countryCode,
		RecordedBy:                  producer,
		RecordedAt:                  time.Now(),
	}

	// expire in 10 years
	expTime := time.Now().AddDate(10, 0, 0).UTC().Truncate(time.Hour * 24)
	rawVC, err := v.compileVINAttestation(vinSubject, expTime)
	if err != nil {
		return nil, richerrors.Error{Err: err, ExternalMsg: "Failed to create VC"}
	}

	err = v.vcRepo.UploadAttestation(ctx, rawVC)
	if err != nil {
		return nil, richerrors.Error{Err: err, ExternalMsg: "Failed to store VC"}
	}
	return rawVC, nil
}

func (v *Service) compileVINAttestation(subject types.VINSubject, expirationDate time.Time) (*cloudevent.RawEvent, error) {
	issuanceDate := time.Now().UTC()

	credential := types.Credential{
		ValidFrom: issuanceDate,
		ValidTo:   expirationDate.UTC(),
	}

	rawSubject, err := json.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential subject: %w", err)
	}
	credential.CredentialSubject = rawSubject

	marshaledCreds, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	signature, err := erc191.SignMessage(marshaledCreds, v.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	cloudEvent := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion:     "1.0",
			ID:              ksuid.New().String(),
			Time:            issuanceDate,
			Source:          sources.DINCSource.String(),
			Subject:         subject.VehicleDID,
			Producer:        subject.RecordedBy,
			Type:            cloudevent.TypeAttestation,
			DataContentType: "application/json",
			DataVersion:     v.VINVCDataVersion,
			Signature:       signature,
		},
		Data: marshaledCreds,
	}

	return &cloudEvent, nil
}
