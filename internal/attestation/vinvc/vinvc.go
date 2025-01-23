// Package vinvc provides the controller for handling VIN VC-related requests.
package vinvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/controllers/ctrlerrors"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const (
	daysInWeek     = 7
	PolygonChainID = 137
)

// Service handles VIN VC-related operations.
type Service struct {
	logger            *zerolog.Logger
	vcRepo            VCRepo
	identityAPI       IdentityAPI
	fingerprintRepo   FingerprintRepo
	vinAPI            VINAPI
	issuer            Issuer
	revokedMap        map[uint32]struct{}
	vehicleNFTAddress string
}

// NewService creates a new Service for VIN VC operations.
func NewService(
	logger *zerolog.Logger,
	vcRepo VCRepo,
	identityService IdentityAPI,
	fingerprintService FingerprintRepo,
	vinService VINAPI,
	issuer Issuer,
	revokedList []uint32,
	vehicleNFTAddress string,
) *Service {
	revokeMap := make(map[uint32]struct{}, len(revokedList))
	for _, id := range revokedList {
		revokeMap[id] = struct{}{}
	}
	return &Service{
		logger:            logger,
		vcRepo:            vcRepo,
		identityAPI:       identityService,
		fingerprintRepo:   fingerprintService,
		vinAPI:            vinService,
		issuer:            issuer,
		revokedMap:        revokeMap,
		vehicleNFTAddress: vehicleNFTAddress,
	}
}

// GetOrCreateVC retrieves or generates a VC for the given token ID.
// if force is true, a new VC is generated regardless of the existing VC.
func (v *Service) GetOrCreateVC(ctx context.Context, tokenID uint32, force bool) error {
	logger := v.logger.With().Uint32("vehicleTokenId", tokenID).Logger()

	if !force && v.hasValidVC(ctx, tokenID) {
		logger.Debug().Msg("Valid VC already exists skipping generation")
		return nil
	}
	return v.GenerateVINVC(ctx, tokenID, &logger)
}

// hasValidVC checks if a valid VC exists for the given token ID.
func (v *Service) hasValidVC(ctx context.Context, tokenID uint32) bool {
	vehicleDID := cloudevent.NFTDID{
		ChainID:         PolygonChainID,
		ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
		TokenID:         tokenID,
	}
	prevVC, err := v.vcRepo.GetLatestVINVC(ctx, vehicleDID)
	if err == nil {
		expireDate, err := time.Parse(time.RFC3339, prevVC.ValidFrom)
		if err == nil && time.Now().Before(expireDate) {
			return true
		}
	}
	return false
}

func (v *Service) GenerateVINVC(ctx context.Context, tokenID uint32, logger *zerolog.Logger) error {
	// get meta data about the vehilce
	vehicleDID := cloudevent.NFTDID{
		ChainID:         PolygonChainID,
		ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
		TokenID:         tokenID,
	}
	vehicleInfo, err := v.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get vehicle info"}
	}

	// get a valid VIN for the vehilce
	validFP, err := v.getValidFingerPrint(ctx, vehicleInfo, "")
	if err != nil {
		return err
	}

	// creatae the subject for the VC
	vinSubject := verifiable.VINSubject{
		VehicleIdentificationNumber: validFP.VIN,
		VehicleTokenID:              tokenID,
		CountryCode:                 "",
		RecordedBy:                  validFP.Producer,
		RecordedAt:                  validFP.Time,
		VehicleContractAddress:      "eth:" + v.vehicleNFTAddress,
	}

	// create the new VC
	expTime := time.Now().AddDate(0, 0, daysInWeek-int(time.Now().Weekday())).UTC().Truncate(time.Hour * 24)
	rawVC, err := v.issuer.CreateVINVC(vinSubject, expTime)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create VC"}
	}
	producerDID, err := cloudevent.DecodeNFTDID(validFP.Producer)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to decode producer DID"}
	}
	// store the VC
	err = v.vcRepo.StoreVINVC(ctx, vehicleDID, producerDID, rawVC)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store VC"}
	}

	return nil
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
			// log the error and continue to the next device if possible
			msg := fmt.Sprintf("Failed to get latest vin message for device %s", device.DID.String())
			err = ctrlerrors.Error{InternalError: err, ExternalMsg: msg}
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
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to decode VIN"}
	}
	if decodedNameSlug != vehicleInfo.NameSlug {
		message := "Invalid VIN Decoding from fingerprint"
		err := fmt.Errorf("decodedNameSlug: %s != identityNameSlug: %s", decodedNameSlug, vehicleInfo.NameSlug)
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: message, Code: fiber.StatusBadRequest}
	}

	return latestFP, nil
}

// GenerateKeyControlDocument generates a new control document for sharing public keys.
func (v *Service) GenerateKeyControlDocument() (json.RawMessage, error) {
	keyDoc, err := v.issuer.CreateKeyControlDoc()
	if err != nil {
		return nil, fmt.Errorf("failed to create key control document: %w", err)
	}
	return keyDoc, nil
}

func (v *Service) GenerateJSONLDDocument() (json.RawMessage, error) {
	jsonLDDoc, err := v.issuer.CreateJSONLDDoc()
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON-LD document: %w", err)
	}
	return jsonLDDoc, nil
}

func (v *Service) GenerateVocabDocument() (json.RawMessage, error) {
	vocabDoc, err := v.issuer.CreateVocabWebpage()
	if err != nil {
		return nil, fmt.Errorf("failed to create vocabulary document: %w", err)
	}
	return vocabDoc, nil
}

// GenerateStatusVC generates a new status VC.
func (v *Service) GenerateStatusVC(tokenID uint32) (json.RawMessage, error) {
	revoked := false
	if _, ok := v.revokedMap[tokenID]; ok {
		revoked = true
	}
	vcData, err := v.issuer.CreateBitstringStatusListVC(tokenID, revoked)
	if err != nil {
		return nil, fmt.Errorf("failed to create VC: %w", err)
	}
	return vcData, nil
}
