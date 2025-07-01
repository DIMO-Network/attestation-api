package pom

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"slices"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/controllers/ctrlerrors"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/convert"
	"github.com/DIMO-Network/model-garage/pkg/hashdog"
	"github.com/DIMO-Network/model-garage/pkg/nativestatus"
	"github.com/DIMO-Network/model-garage/pkg/ruptela"
	"github.com/DIMO-Network/model-garage/pkg/twilio"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/shared/set"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/uber/h3-go/v4"
)

const (
	autoPiManufacturer  = "AutoPi"
	hashDogManufacturer = "HashDog"
	ruptelaManufacturer = "Ruptela"
	// h3Resolution resolution for h3 hex 8 ~= 0.737327598 km2
	h3Resolution = 8
)

var errNoLocation = fmt.Errorf("no location data found")

var acceptableStatusSources = set.New(
	// Tesla source
	"dimo/integration/22N2xaPOq2WW2gAHBHd0Ikn4Zob",
	// Smartcar source
	"dimo/integration/26A5Dk3vvvQutjSyF0Jka2DP5lg",
)

type Service struct {
	logger                 zerolog.Logger
	identityAPI            IdentityAPI
	connectivityRepo       ConnectivityRepo
	vcRepo                 VCRepo
	issuer                 Issuer
	vehicleContractAddress common.Address
	chainID                uint64
}

func NewService(logger *zerolog.Logger, identityAPI IdentityAPI, connectivityRepo ConnectivityRepo, vcRepo VCRepo, issuer Issuer, vehicleContractAddress string, chainID int64) (*Service, error) {
	if !common.IsHexAddress(vehicleContractAddress) {
		return nil, fmt.Errorf("invalid vehicle contract address: %s", vehicleContractAddress)
	}
	return &Service{
		logger:                 *logger,
		identityAPI:            identityAPI,
		connectivityRepo:       connectivityRepo,
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
	logger := s.logger.With().Uint32("vehicleTokenId", tokenID).Logger()

	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, vehicleDID)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to get vehicle info"}
	}

	pairedDevice, locations, err := s.getLocationForVehicle(ctx, vehicleInfo, &logger)
	if err != nil {
		msg := "Failed to get location data"
		if errors.Is(err, errNoLocation) {
			msg = "No movement detected in the last 7 days"
		}
		return ctrlerrors.Error{InternalError: err, ExternalMsg: msg}
	}

	pomSubject := POMSubject{
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress.Hex(),
		RecordedBy:             pairedDevice.DID.String(),
		Locations:              locations,
	}

	vc, err := s.issuer.CreatePOMVC(pomSubject)
	if err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create POM VC"}
	}

	if err = s.vcRepo.StorePOMVC(ctx, vehicleDID.String(), pairedDevice.DID.String(), vc); err != nil {
		return ctrlerrors.Error{InternalError: err, ExternalMsg: "Failed to create POM VC"}
	}

	return nil
}

// getLocationForVehicle retrieves location data from paired devices.
func (s *Service) getLocationForVehicle(ctx context.Context, vehicleInfo *models.VehicleInfo, logger *zerolog.Logger) (*models.PairedDevice, []Location, error) {
	slices.SortStableFunc(vehicleInfo.PairedDevices, pairedDeviceSorter)
	for _, device := range vehicleInfo.PairedDevices {
		var locations []Location
		var err error

		switch {
		case device.Type == models.DeviceTypeAftermarket && device.ManufacturerName == autoPiManufacturer:
			locations, err = s.pullAutoPiEvents(ctx, &device)
		case device.Type == models.DeviceTypeAftermarket && device.ManufacturerName == hashDogManufacturer:
			locations, err = s.pullMacaronEvents(ctx, &device)
		case device.Type == models.DeviceTypeAftermarket && device.ManufacturerName == ruptelaManufacturer:
			locations, err = s.pullRuptelaEvents(ctx, vehicleInfo.DID)
		default:
			locations, err = s.pullStatusEvents(ctx, vehicleInfo.DID)
		}
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

// pullAutoPiEvents retrieves AutoPi events and extracts locations.
func (s *Service) pullAutoPiEvents(ctx context.Context, device *models.PairedDevice) ([]Location, error) {
	fetchEvents := func(after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
		return s.connectivityRepo.GetAutoPiEvents(ctx, device, after, before, limit)
	}
	return s.pullEvents(ctx, fetchEvents, parseAutoPiEvent)
}

// pullMacaronEvents retrieves Macaron events and extracts locations.
func (s *Service) pullMacaronEvents(ctx context.Context, device *models.PairedDevice) ([]Location, error) {
	fetchEvents := func(after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
		return s.connectivityRepo.GetHashDogEvents(ctx, device, after, before, limit)
	}
	return s.pullEvents(ctx, fetchEvents, parseMacaronEvent)
}

// pullStatusEvents retrieves synthetic events and extracts locations.
func (s *Service) pullStatusEvents(ctx context.Context, vehicleDID cloudevent.ERC721DID) ([]Location, error) {
	fetchEvents := func(after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
		return s.connectivityRepo.GetSyntheticstatusEvents(ctx, vehicleDID, after, before, limit)
	}
	return s.pullEvents(ctx, fetchEvents, parseSyntheticEvent)
}

// pullRuptelaEvents retrieves Ruptela Status events and extracts locations.
func (s *Service) pullRuptelaEvents(ctx context.Context, vehicleDID cloudevent.ERC721DID) ([]Location, error) {
	fetchEvents := func(after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
		return s.connectivityRepo.GetRuptelaStatusEvents(ctx, vehicleDID, after, before, limit)
	}
	return s.pullEvents(ctx, fetchEvents, parseRuptelaEvent)
}

// pullEvents is a generic function for fetching events and extracting locations.
func (s *Service) pullEvents(ctx context.Context, fetchEvents func(time.Time, time.Time, int) ([]cloudevent.CloudEvent[json.RawMessage], error), parseEvent func(cloudevent.CloudEvent[json.RawMessage]) (cloudevent.CloudEvent[any], error)) ([]Location, error) {
	limit := 10
	weekAgo := time.Now().Add(-7 * 24 * time.Hour)
	before := time.Now()

	var firstEvent cloudevent.CloudEvent[any]

	for weekAgo.Before(before) {
		events, err := fetchEvents(weekAgo, before, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get events: %w", err)
		}
		if len(events) == 0 {
			break
		}

		for _, rawEvent := range events {
			cloudEvent, err := parseEvent(rawEvent)
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
	if a.Type == b.Type {
		if a.ManufacturerName == b.ManufacturerName {
			return cmp.Compare(a.Address, b.Address)
		}
		return cmp.Compare(a.ManufacturerName, b.ManufacturerName)
	}
	if a.Type == "aftermarket" {
		return -1
	}
	if b.Type == "aftermarket" {
		return 1
	}
	return cmp.Compare(a.Type, b.Type)
}

// compareLocations compares locations of two events and returns verifiable locations.
func compareLocations(firstEvent, curEvent cloudevent.CloudEvent[any]) []Location {
	if reflect.TypeOf(firstEvent.Data) != reflect.TypeOf(curEvent.Data) {
		return nil
	}

	switch currData := curEvent.Data.(type) {
	case twilio.ConnectionEvent:
		curCellID := currData.Location.CellID
		firstCellID := firstEvent.Data.(twilio.ConnectionEvent).Location.CellID
		if firstCellID != curCellID && firstCellID != "" {
			return []Location{
				{
					LocationType:  LocationTypeCellID,
					LocationValue: CellID{CellID: firstCellID},
					Timestamp:     firstEvent.Time,
				},
				{
					LocationType:  LocationTypeCellID,
					LocationValue: CellID{CellID: curCellID},
					Timestamp:     curEvent.Time,
				},
			}
		}
	case hashdog.Data:
		if firstEvent.Equals(curEvent.CloudEventHeader) {
			// gatway differences must be from different events
			return nil
		}
		firstGatewayID := getFirstGWMeta(firstEvent.Data.(hashdog.Data).Via).GatewayID
		for _, via := range currData.Via {
			if via.Metadata.GatewayID != "" && firstGatewayID != via.Metadata.GatewayID {
				return []Location{
					{
						LocationType:  LocationTypeGatewayID,
						LocationValue: GatewayID{GatewayID: firstGatewayID},
						Timestamp:     firstEvent.Time,
					},
					{
						LocationType:  LocationTypeGatewayID,
						LocationValue: GatewayID{GatewayID: via.Metadata.GatewayID},
						Timestamp:     curEvent.Time,
					},
				}
			}
		}
	case []h3.Cell:
		currCells := currData
		firstCells := firstEvent.Data.([]h3.Cell)
		if len(firstCells) == 0 {
			return nil
		}
		firstCell := firstCells[0]
		for _, cell := range currCells {
			if cell != firstCell {
				return []Location{
					{
						LocationType:  LocationTypeH3Cell,
						LocationValue: H3Cell{CellID: cell.String()},
						Timestamp:     firstEvent.Time,
					},
					{
						LocationType:  LocationTypeH3Cell,
						LocationValue: H3Cell{CellID: cell.String()},
						Timestamp:     curEvent.Time,
					},
				}
			}
		}
	}
	return nil
}

// parseAutoPiEvent parses twilo events and returns data for events with cell data.
func parseAutoPiEvent(event cloudevent.CloudEvent[json.RawMessage]) (cloudevent.CloudEvent[any], error) {
	var eventData twilio.ConnectionEvent
	err := json.Unmarshal(event.Data, &eventData)
	if err != nil {
		return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to unmarshal twilio event: %w", err)
	}
	// only return events with cell data
	if eventData.Location == nil || eventData.Location.CellID == "" {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader, Data: eventData}, nil
}

// parseMacaronEvent parses hashdog events and returns data for events with gateway data.
func parseMacaronEvent(event cloudevent.CloudEvent[json.RawMessage]) (cloudevent.CloudEvent[any], error) {
	var eventData hashdog.Data
	err := json.Unmarshal(event.Data, &eventData)
	if err != nil {
		return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to unmarshal hashdog event: %w", err)
	}

	// only return events with gateway data
	if getFirstGWMeta(eventData.Via).GatewayID == "" {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}

	return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader, Data: eventData}, nil
}

// parseSyntheticEvent parses status events and returns data for events with lat and long data.
func parseSyntheticEvent(event cloudevent.CloudEvent[json.RawMessage]) (cloudevent.CloudEvent[any], error) {
	if !acceptableStatusSources.Contains(event.Source) {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to marshal event data: %w", err)
	}

	// TODO this context argument will be going away.
	signals, err := nativestatus.SignalsFromPayload(context.TODO(), nil, data)
	if err != nil {
		return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to convert signals: %w", err)
	}
	latLong, ok := getH3Cells(signals)
	if !ok {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader, Data: latLong}, nil
}

func parseRuptelaEvent(event cloudevent.CloudEvent[json.RawMessage]) (cloudevent.CloudEvent[any], error) {
	signals, err := ruptela.DecodeStatusSignals(event)
	if err != nil {
		convErr := convert.ConversionError{}
		if !errors.As(err, &convErr) || len(convErr.DecodedSignals) == 0 {
			return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to decode signals: %w", err)
		}
		signals = convErr.DecodedSignals
	}
	latLong, ok := getH3Cells(signals)
	if !ok {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader, Data: latLong}, nil
}

// getFirstGWMeta retrieves the first gateway metadata from a list of Via events.
func getFirstGWMeta(vias []hashdog.Via) hashdog.GWMetadata {
	for _, via := range vias {
		if via.Metadata.GatewayID != "" {
			return via.Metadata
		}
	}
	return hashdog.GWMetadata{}
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
