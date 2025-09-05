package pom

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"slices"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/types"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/fetch-api/pkg/grpc"
	"github.com/DIMO-Network/model-garage/pkg/modules"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/uber/h3-go/v4"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// h3Resolution resolution for h3 hex 8 ~= 0.737327598 km2
	h3Resolution = 8
)

var errNoLocation = fmt.Errorf("no location data found")

type Service struct {
	identityAPI            IdentityAPI
	vcRepo                 VCRepo
	issuer                 Issuer
	vehicleContractAddress common.Address
	chainID                uint64

	fetchService *fetchapi.FetchAPIService
}

func NewService(identityAPI IdentityAPI, vcRepo VCRepo, issuer Issuer, vehicleContractAddress string, chainID int64) (*Service, error) {
	if !common.IsHexAddress(vehicleContractAddress) {
		return nil, fmt.Errorf("invalid vehicle contract address: %s", vehicleContractAddress)
	}
	return &Service{
		identityAPI:            identityAPI,
		vcRepo:                 vcRepo,
		issuer:                 issuer,
		vehicleContractAddress: common.HexToAddress(vehicleContractAddress),
		chainID:                uint64(chainID),
	}, nil
}

// CreatePOMVC generates a Proof of Movement VC.
func (s *Service) CreatePOMVC(ctx context.Context, tokenID uint32) error {
	vehicleDID := cloudevent.ERC721DID{
		ChainID:         s.chainID,
		TokenID:         big.NewInt(int64(tokenID)),
		ContractAddress: s.vehicleContractAddress,
	}

	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return richerrors.Error{Err: err, ExternalMsg: "Failed to get vehicle info", Code: http.StatusInternalServerError}
	}

	pairedDevice, locations, err := s.getLocationForVehicle(ctx, vehicleInfo)
	if err != nil {
		msg := "Failed to get location data"
		if errors.Is(err, errNoLocation) {
			msg = "No movement detected in the last 7 days"
		}
		return richerrors.Error{Err: err, ExternalMsg: msg, Code: http.StatusNotFound}
	}

	pomSubject := types.POMSubject{
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress.Hex(),
		RecordedBy:             pairedDevice.DID.String(),
		Locations:              locations,
	}

	vc, err := s.issuer.CreatePOMVC(pomSubject)
	if err != nil {
		return richerrors.Error{Err: err, ExternalMsg: "Failed to create POM VC", Code: http.StatusInternalServerError}
	}

	if err = s.vcRepo.StorePOMVC(ctx, vehicleDID.String(), pairedDevice.DID.String(), vc); err != nil {
		return richerrors.Error{Err: err, ExternalMsg: "Failed to create POM VC", Code: http.StatusInternalServerError}
	}

	return nil
}

// getLocationForVehicle retrieves location data from paired devices.
func (s *Service) getLocationForVehicle(ctx context.Context, vehicleInfo *models.VehicleInfo) (*models.PairedDevice, []types.Location, error) {
	slices.SortStableFunc(vehicleInfo.PairedDevices, pairedDeviceSorter)
	for _, device := range vehicleInfo.PairedDevices {
		locations, err := s.pullEvents(ctx, vehicleInfo.DID, device.DID)
		if err == nil {
			return &device, locations, nil
		}
		if errors.Is(err, errNoLocation) {
			// if no location data found try the next device
			continue
		}
		return nil, nil, err
	}
	return nil, nil, errNoLocation
}

func (s *Service) fetchEvents(ctx context.Context, vehicleDID, deviceDID cloudevent.ERC721DID, after, before time.Time, limit int) ([]cloudevent.RawEvent, error) {
	statusType := cloudevent.TypeStatus
	opts := &grpc.SearchOptions{
		Subject:  wrapperspb.String(vehicleDID.String()),
		Producer: wrapperspb.String(deviceDID.String()),
		// Source:   wrapperspb.String(source),
		Type: wrapperspb.String(statusType),
	}
	dataObj, err := s.fetchService.GetAllCloudEvents(ctx, opts, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint message: %w", err)
	}
	return dataObj, nil
}

// pullEvents is a generic function for fetching events and extracting locations.
func (s *Service) pullEvents(ctx context.Context, vehicleDID, deviceDID cloudevent.ERC721DID) ([]types.Location, error) {
	limit := 10
	weekAgo := time.Now().Add(-7 * 24 * time.Hour)
	before := time.Now()

	var firstEvent cloudevent.CloudEvent[[]h3.Cell]

	for weekAgo.Before(before) {
		events, err := s.fetchEvents(ctx, vehicleDID, deviceDID, weekAgo, before, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get events: %w", err)
		}
		if len(events) == 0 {
			break
		}

		for _, rawEvent := range events {
			cloudEvent, err := parseEvent(ctx, rawEvent)
			if err != nil {
				return nil, err
			}
			before = cloudEvent.Time

			// Skip events without location data
			if cloudEvent.Data == nil {
				continue
			}

			if firstEvent.Data == nil {
				firstEvent = cloudEvent
			}

			// Compare with the first event
			if locations := compareLocations(firstEvent, cloudEvent); len(locations) > 0 {
				return locations, nil
			}
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}
	return nil, errNoLocation
}

// pairedDeviceSorter compares two paired devices.
func pairedDeviceSorter(a, b models.PairedDevice) int {
	return cmp.Compare(a.DID.String(), b.DID.String())
}

// compareLocations compares locations of two events and returns verifiable locations.
func compareLocations(firstEvent, curEvent cloudevent.CloudEvent[[]h3.Cell]) []types.Location {
	currCells := curEvent.Data
	firstCells := firstEvent.Data
	if len(firstCells) == 0 {
		return nil
	}
	firstCell := firstCells[0]
	for _, cell := range currCells {
		if cell != firstCell {
			return []types.Location{
				{
					LocationType:  types.LocationTypeH3Cell,
					LocationValue: types.H3Cell{CellID: cell.String()},
					Timestamp:     firstEvent.Time,
				},
				{
					LocationType:  types.LocationTypeH3Cell,
					LocationValue: types.H3Cell{CellID: cell.String()},
					Timestamp:     curEvent.Time,
				},
			}
		}
	}
	return nil
}

// parseEvent parses status events and returns data for events with lat and long data.
func parseEvent(ctx context.Context, event cloudevent.RawEvent) (cloudevent.CloudEvent[[]h3.Cell], error) {
	signals, err := modules.ConvertToSignals(ctx, event.Source, event)
	if err != nil {
		return cloudevent.CloudEvent[[]h3.Cell]{}, fmt.Errorf("failed to convert signals: %w", err)
	}
	latLong, ok := getH3Cells(signals)
	if !ok {
		return cloudevent.CloudEvent[[]h3.Cell]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	return cloudevent.CloudEvent[[]h3.Cell]{CloudEventHeader: event.CloudEventHeader, Data: latLong}, nil
}

func getH3Cells(signals []vss.Signal) ([]h3.Cell, bool) {
	latLongPairs := map[int64]LatLng{}
	for _, signal := range signals {
		timeInSecs := signal.Timestamp.Unix()
		switch signal.Name {
		case vss.FieldCurrentLocationLatitude:
			latLng := latLongPairs[timeInSecs]
			latLng.Latitude = &signal.ValueNumber
			latLongPairs[timeInSecs] = latLng
		case vss.FieldCurrentLocationLongitude:
			latLng := latLongPairs[timeInSecs]
			latLng.Longitude = &signal.ValueNumber
			latLongPairs[timeInSecs] = latLng
		}
	}
	var cells []h3.Cell
	for _, latLng := range latLongPairs {
		if latLng.Latitude != nil && latLng.Longitude != nil {
			h3LatLng := h3.NewLatLng(*latLng.Latitude, *latLng.Longitude)
			cell, err := h3.LatLngToCell(h3LatLng, h3Resolution)
			if err != nil {
				return nil, false
			}
			cells = append(cells, cell)
		}
	}

	return cells, len(cells) > 0
}

type LatLng struct {
	Latitude  *float64 `json:"latitude"`
	Longitude *float64 `json:"longitude"`
}
