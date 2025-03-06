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
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
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
	issuer            Issuer
	revokedMap        map[uint32]struct{}
	vehicleNFTAddress string
	chainID           uint64
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
	chainID int64,
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
		chainID:           uint64(chainID),
	}
}

// GetOrCreateVC retrieves or generates a VC for the given token ID.
// if force is true, a new VC is generated regardless of the existing VC.
func (v *Service) GetOrCreateVC(ctx context.Context, tokenID uint32, before time.Time, force bool) (json.RawMessage, error) {
	logger := v.logger.With().Uint32("vehicleTokenId", tokenID).Logger()

	if !force {
		// check if a valid VC already exists and return it instead of generating a new one
		rawVC, err := v.getValidVC(ctx, tokenID, before)
		if err == nil {
			logger.Debug().Msg("Valid VC already exists skipping generation")
			return rawVC, nil
		}
	}

	return v.GenerateVINVCAndStore(ctx, tokenID)
}

// getValidVC checks if an unexpired VC exists for the given token ID.
func (v *Service) getValidVC(ctx context.Context, tokenID uint32, before time.Time) (json.RawMessage, error) {
	vehicleDID := cloudevent.NFTDID{
		ChainID:         v.chainID,
		ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
		TokenID:         tokenID,
	}
	prevVC, err := v.vcRepo.GetLatestVINVC(ctx, vehicleDID)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get VC"}
	}
	if vcIsExpired(prevVC) {
		return nil, ctrlerrors.Error{ExternalMsg: "VC is expired"}
	}
	var vinSubject verifiable.VINSubject
	err = json.Unmarshal(prevVC.CredentialSubject, &vinSubject)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to unmarshal VIN VC Subject"}
	}

	if !before.IsZero() && vinSubject.RecordedAt.After(before) {
		return nil, ctrlerrors.Error{ExternalMsg: "VC is too new"}
	}

	rawVC, err := json.Marshal(prevVC)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to marshal VC"}
	}

	return rawVC, nil
}

func vcIsExpired(vc *verifiable.Credential) bool {
	expireDate, err := time.Parse(time.RFC3339, vc.ValidFrom)
	if err != nil {
		return true
	}
	return time.Now().After(expireDate)
}

// GenerateVINVC generates a new VIN VC and returns it.
func (v *Service) GenerateVINVC(ctx context.Context, tokenID uint32) (json.RawMessage, error) {
	_, _, rawVC, err := v.generateVINVC(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	return rawVC, nil
}

// GenerateVINVCAndStore generates a new VIN VC and stores it in Object Storage.
func (v *Service) GenerateVINVCAndStore(ctx context.Context, tokenID uint32) (json.RawMessage, error) {
	vehicleDID, producer, rawVC, err := v.generateVINVC(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	producerDID, err := cloudevent.DecodeNFTDID(producer)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to decode producer DID"}
	}
	err = v.vcRepo.StoreVINVC(ctx, vehicleDID.String(), producerDID.String(), rawVC)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store VC"}
	}
	return rawVC, nil
}

func (v *Service) generateVINVC(ctx context.Context, tokenID uint32) (cloudevent.NFTDID, string, json.RawMessage, error) {
	// get meta data about the vehilce
	vehicleDID := cloudevent.NFTDID{
		ChainID:         v.chainID,
		ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
		TokenID:         tokenID,
	}
	vehicleInfo, err := v.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return cloudevent.NFTDID{}, "", nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get vehicle info"}
	}

	// get a valid VIN for the vehilce
	validFP, err := v.getValidFingerPrint(ctx, vehicleInfo, "")
	if err != nil {
		return cloudevent.NFTDID{}, "", nil, err
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
		return cloudevent.NFTDID{}, "", nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create VC"}
	}

	return vehicleDID, validFP.Producer, rawVC, nil
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
		err := fmt.Errorf("decodedNameSlug: %s != identityNameSlug: %s vin = %s", decodedNameSlug, vehicleInfo.NameSlug, latestFP.VIN)
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: message, Code: fiber.StatusBadRequest}
	}

	return latestFP, nil
}

func (v *Service) GenerateManualVC(ctx context.Context, tokenID uint32, vin string, countryCode string) (json.RawMessage, error) {
	producer := cloudevent.EthrDID{
		ChainID:         v.chainID,
		ContractAddress: sources.DINCSource,
	}.String()

	// create the subject for the Manually created VC
	vinSubject := verifiable.VINSubject{
		VehicleIdentificationNumber: vin,
		VehicleTokenID:              tokenID,
		CountryCode:                 countryCode,
		RecordedBy:                  producer,
		RecordedAt:                  time.Now(),
	}

	vehicleDID := cloudevent.NFTDID{
		ChainID:         v.chainID,
		ContractAddress: common.HexToAddress(v.vehicleNFTAddress),
		TokenID:         tokenID,
	}

	// create the new VC
	expTime := time.Now().AddDate(0, 0, daysInWeek-int(time.Now().Weekday())).UTC().Truncate(time.Hour * 24)
	rawVC, err := v.issuer.CreateVINVC(vinSubject, expTime)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create VC"}
	}

	err = v.vcRepo.StoreVINVC(ctx, vehicleDID.String(), producer, rawVC)
	if err != nil {
		return nil, ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store VC"}
	}
	return rawVC, nil
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
