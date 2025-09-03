package vehiclepositionvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/client/telemetryapi"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/ctrlerrors"
	"github.com/DIMO-Network/attestation-api/internal/erc191"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/ethereum/go-ethereum/common"
	"github.com/segmentio/ksuid"
	"github.com/uber/h3-go/v4"
)

const (
	// h3Resolution resolution for h3 hex 8 ~= 0.737327598 km2
	h3Resolution = 8
)

// Service handles VehiclePositionVC-related operations.
type Service struct {
	vcRepo                 VCRepo
	identityAPI            IdentityAPI
	telemetryAPI           TelemetryAPI
	vehicleContractAddress common.Address
	chainID                uint64
	privateKey             *ecdsa.PrivateKey
	dataVersion            string
}

// NewService creates a new Service for VehiclePositionVC operations.
func NewService(
	vcRepo VCRepo,
	identityAPI IdentityAPI,
	telemetryAPI TelemetryAPI,
	settings *config.Settings,
	privateKey *ecdsa.PrivateKey,
) *Service {
	return &Service{
		vcRepo:                 vcRepo,
		identityAPI:            identityAPI,
		telemetryAPI:           telemetryAPI,
		vehicleContractAddress: common.HexToAddress(settings.VehicleNFTAddress),
		chainID:                uint64(settings.DIMORegistryChainID),
		privateKey:             privateKey,
		dataVersion:            "1.0.0", // You may want to add this to settings
	}
}

// CreateVehiclePositionVC creates a VehiclePositionVC for a specific timestamp.
func (s *Service) CreateVehiclePositionVC(ctx context.Context, tokenID uint32, requestedTimestamp time.Time, jwtToken string) error {
	vehicleDID := cloudevent.ERC721DID{
		ChainID:         s.chainID,
		TokenID:         big.NewInt(int64(tokenID)),
		ContractAddress: s.vehicleContractAddress,
	}

	location, err := s.findClosestLocation(ctx, vehicleDID, requestedTimestamp, jwtToken)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to find location data"}
	}

	subject := types.VehiclePositionVCSubject{
		VehicleDID:         vehicleDID.String(),
		Location:           *location,
		RequestedTimestamp: requestedTimestamp,
	}

	vc, err := s.createAttestation(subject)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create VehiclePositionVC"}
	}

	if err = s.vcRepo.UploadAttestation(ctx, vc); err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to store VehiclePositionVC"}
	}

	return nil
}

// findClosestLocation finds the location closest to the requested timestamp using telemetry API.
func (s *Service) findClosestLocation(ctx context.Context, vehicleInfo cloudevent.ERC721DID, requestedTime time.Time, jwtToken string) (*types.Location, error) {
	// Define time window around requested timestamp (1 hour before and after)
	startTime := requestedTime.Add(-time.Hour)
	endTime := requestedTime.Add(time.Hour)

	options := telemetryapi.TelemetryQueryOptions{
		TokenID:   vehicleInfo.TokenID,
		StartDate: startTime,
		EndDate:   endTime,
		Signals:   []string{"currentLocationLatitude", "currentLocationLongitude", "currentLocationApproximateLatitude", "currentLocationApproximateLongitude"},
	}

	// Get historical telemetry data
	signals, err := s.telemetryAPI.GetHistoricalDataWithAuth(ctx, options, jwtToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get telemetry data: %w", err)
	}

	// Find the location closest to requested timestamp
	var closestLocation *types.Location
	var closestTimeDiff time.Duration

	h3Locations := signalsToH3Values(signals)

	for _, h3Location := range h3Locations {
		timeDiff := absTimeDiff(h3Location.Timestamp, requestedTime)
		if closestLocation == nil || timeDiff < closestTimeDiff {
			closestLocation = &h3Location
			closestTimeDiff = timeDiff
		}
	}

	if closestLocation == nil {
		return nil, fmt.Errorf("no location data found in telemetry")
	}

	return closestLocation, nil
}

// createAttestation creates the attestation cloud event.
func (s *Service) createAttestation(subject types.VehiclePositionVCSubject) (*cloudevent.RawEvent, error) {
	issuanceDate := time.Now().UTC()
	expirationDate := issuanceDate.Add(30 * 24 * time.Hour) // Valid for 30 days

	credential := types.Credential{
		ValidFrom: issuanceDate,
		ValidTo:   expirationDate,
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

	signature, err := erc191.SignMessage(marshaledCreds, s.privateKey)
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
			Type:            cloudevent.TypeAttestation,
			DataContentType: "application/json",
			DataVersion:     s.dataVersion,
			Signature:       signature,
		},
		Data: marshaledCreds,
	}

	return &cloudEvent, nil
}

func signalsToH3Values(signals []telemetryapi.Signal) []types.Location {
	pairs := map[time.Time]vss.Location{}
	for _, signal := range signals {
		location := pairs[signal.Timestamp]
		switch signal.Name {
		case vss.FieldCurrentLocationLatitude, "currentLocationApproximateLatitude":
			if lat, ok := signal.Value.(float64); ok {
				location.Latitude = lat
			}
		case vss.FieldCurrentLocationLongitude, "currentLocationApproximateLongitude":
			if lng, ok := signal.Value.(float64); ok {
				location.Longitude = lng
			}
		}
		pairs[signal.Timestamp] = location
	}
	h3Locations := make([]types.Location, 0, len(pairs))
	for timestamp, pair := range pairs {
		cell, err := h3.LatLngToCell(h3.NewLatLng(pair.Latitude, pair.Longitude), h3Resolution)
		if err != nil {
			continue
		}
		location := types.Location{
			LocationType:  types.LocationTypeH3Cell,
			LocationValue: types.H3Cell{CellID: cell.String()},
			Timestamp:     timestamp,
		}
		h3Locations = append(h3Locations, location)
	}
	return h3Locations
}

// absTimeDiff returns the absolute difference between two times.
func absTimeDiff(a, b time.Time) time.Duration {
	diff := a.Sub(b)
	if diff < 0 {
		return -diff
	}
	return diff
}
