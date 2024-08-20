package pom

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/lorawan"
	"github.com/DIMO-Network/model-garage/pkg/twilio"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/model-garage/pkg/vss/convert"
	"github.com/DIMO-Network/shared/set"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const (
	autoPiManufacturer  = "AutoPi"
	hashDogManufacturer = "HashDog"
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
	vehicleContractAddress string
}

func NewService(logger *zerolog.Logger, identityAPI IdentityAPI, connectivityRepo ConnectivityRepo, vcRepo VCRepo, issuer Issuer, vehicleContractAddress string) *Service {
	return &Service{
		logger:                 *logger,
		identityAPI:            identityAPI,
		connectivityRepo:       connectivityRepo,
		vcRepo:                 vcRepo,
		issuer:                 issuer,
		vehicleContractAddress: vehicleContractAddress,
	}
}

// CreatePOMVC generates a Proof of Movement VC.
func (s *Service) CreatePOMVC(ctx context.Context, tokenID uint32) error {
	logger := s.logger.With().Uint32("vehicleTokenId", tokenID).Logger()

	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, tokenID)
	if err != nil {
		return handleError(err, &logger, "Failed to get vehicle info")
	}

	pairedDevice, locations, err := s.getLocationForVehicle(ctx, vehicleInfo, &logger)
	if err != nil {
		return handleError(err, &logger, "Failed to get locations")
	}

	pomSubject := verifiable.POMSubject{
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress,
		RecordedBy:             pairedDevice.Address.Hex(),
		Locations:              locations,
	}

	vc, err := s.issuer.CreatePOMVC(pomSubject)
	if err != nil {
		return handleError(err, &logger, "Failed to create POM VC")
	}

	if err = s.vcRepo.StorePOMVC(ctx, tokenID, vc); err != nil {
		return handleError(err, &logger, "Failed to store POM VC")
	}

	return nil
}

// getLocationForVehicle retrieves location data from paired devices.
func (s *Service) getLocationForVehicle(ctx context.Context, vehicleInfo *models.VehicleInfo, logger *zerolog.Logger) (*models.PairedDevice, []verifiable.Location, error) {
	slices.SortStableFunc(vehicleInfo.PairedDevices, pairedDeviceSorter)
	for _, device := range vehicleInfo.PairedDevices {
		var locations []verifiable.Location
		var err error

		switch {
		case device.Type == models.DeviceTypeAftermarket && device.ManufacturerName == autoPiManufacturer:
			locations, err = s.pullAutoPiEvents(ctx, device.IMEI)
		case device.Type == models.DeviceTypeAftermarket && device.ManufacturerName == hashDogManufacturer:
			locations, err = s.pullMacaronEvents(ctx, device.Address)
		default:
			locations, err = s.pullStatusEvents(ctx, vehicleInfo.TokenID)
		}
		if err == nil {
			return &device, locations, nil
		}
		if !errors.Is(err, errNoLocation) {
			return nil, nil, err
		}
	}
	return nil, nil, errNoLocation
}

// pullAutoPiEvents retrieves AutoPi events and extracts locations.
func (s *Service) pullAutoPiEvents(ctx context.Context, deviceIMEI string) ([]verifiable.Location, error) {
	return s.pullEvents(ctx, func(after, before time.Time, limit int) ([][]byte, error) {
		return s.connectivityRepo.GetAutoPiEvents(ctx, deviceIMEI, after, before, limit)
	}, parseAutoPiEvent)
}

// pullMacaronEvents retrieves Macaron events and extracts locations.
func (s *Service) pullMacaronEvents(ctx context.Context, deviceAddr common.Address) ([]verifiable.Location, error) {
	return s.pullEvents(ctx, func(after, before time.Time, limit int) ([][]byte, error) {
		return s.connectivityRepo.GetHashDogEvents(ctx, deviceAddr, after, before, limit)
	}, parseMacaronEvent)
}

// pullStatusEvents retrieves Status events and extracts locations.
func (s *Service) pullStatusEvents(ctx context.Context, vehicleTokenID uint32) ([]verifiable.Location, error) {
	return s.pullEvents(ctx, func(after, before time.Time, limit int) ([][]byte, error) {
		return s.connectivityRepo.GetStatusEvents(ctx, vehicleTokenID, after, before, limit)
	}, parseStatusEvent)
}

// pullEvents is a generic function for fetching events and extracting locations.
func (s *Service) pullEvents(ctx context.Context, fetchEvents func(time.Time, time.Time, int) ([][]byte, error), parseEvent func([]byte) (cloudevent.CloudEvent[any], error)) ([]verifiable.Location, error) {
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
				continue
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
			return a.Address.Cmp(b.Address)
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
func compareLocations(firstEvent, curEvent cloudevent.CloudEvent[any]) []verifiable.Location {
	switch currData := curEvent.Data.(type) {
	case twilio.ConnectionEvent:
		firstCellID, curCellID := firstEvent.Data.(twilio.ConnectionEvent).Location.CellID, currData.Location.CellID
		if firstCellID != curCellID && firstCellID != "" {
			return []verifiable.Location{
				{
					LocationType:  "cell_id",
					LocationValue: verifiable.CellID{CellID: firstCellID},
					Timestamp:     firstEvent.Time,
				},
				{
					LocationType:  "cell_id",
					LocationValue: verifiable.CellID{CellID: curCellID},
					Timestamp:     curEvent.Time,
				},
			}
		}
	case lorawan.Data:
		firstGatewayID, curGatewayID := getFirstGWMeta(firstEvent.Data.(lorawan.Data).Via).GatewayID, getFirstGWMeta(currData.Via).GatewayID
		if firstGatewayID != curGatewayID && firstGatewayID != "" {
			return []verifiable.Location{
				{
					LocationType:  "gateway_id",
					LocationValue: verifiable.GatewayID{GatewayID: firstGatewayID},
					Timestamp:     firstEvent.Time,
				},
				{
					LocationType:  "gateway_id",
					LocationValue: verifiable.GatewayID{GatewayID: curGatewayID},
					Timestamp:     curEvent.Time,
				},
			}
		}
	case LatLongData:
		firstLatLong, curLatLong := firstEvent.Data.(LatLongData), currData
		dist := distance(firstLatLong.Latitude, firstLatLong.Longitude, curLatLong.Latitude, curLatLong.Longitude)
		if dist > 0.5 {
			return []verifiable.Location{
				{
					LocationType:  "lat_lng",
					LocationValue: verifiable.LatLng{Latitude: firstLatLong.Latitude, Longitude: firstLatLong.Longitude},
					Timestamp:     firstEvent.Time,
				},
				{
					LocationType:  "lat_lng",
					LocationValue: verifiable.LatLng{Latitude: curLatLong.Latitude, Longitude: curLatLong.Longitude},
					Timestamp:     curEvent.Time,
				},
			}
		}
	}
	return nil
}

// parseAutoPiEvent parses twilo events and returns data for events with cell data.
func parseAutoPiEvent(data []byte) (cloudevent.CloudEvent[any], error) {
	var event cloudevent.CloudEvent[twilio.ConnectionEvent]
	err := json.Unmarshal(data, &event)
	if err != nil {
		return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to unmarshal twilio event: %w", err)
	}
	// only return events with cell data
	if event.Data.Location == nil || event.Data.Location.CellID == "" {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	return cloudevent.CloudEvent[any]{
		CloudEventHeader: event.CloudEventHeader,
		Data:             event.Data}, nil
}

// parseMacaronEvent parses lorawan events and returns data for events with gateway data.
func parseMacaronEvent(data []byte) (cloudevent.CloudEvent[any], error) {
	var event cloudevent.CloudEvent[lorawan.Data]
	err := json.Unmarshal(data, &event)
	if err != nil {
		return cloudevent.CloudEvent[any]{}, fmt.Errorf("failed to unmarshal lorawan event: %w", err)
	}

	// only return events with gateway data
	if getFirstGWMeta(event.Data.Via).GatewayID == "" {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}

	return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader, Data: event.Data}, nil
}

// parseStatusEvent parses status events and returns data for events with lat and long data.
func parseStatusEvent(data []byte) (cloudevent.CloudEvent[any], error) {
	var event cloudevent.CloudEvent[any]
	err := json.Unmarshal(data, &event)
	if err != nil {
		return event, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	if !acceptableStatusSources.Contains(event.Source) {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	signals, err := convert.SignalsFromPayload(context.TODO(), nil, data)
	if err != nil {
		return event, fmt.Errorf("failed to convert signals: %w", err)
	}
	latLong, ok := getLatAndLong(signals)
	if !ok {
		return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader}, nil
	}
	return cloudevent.CloudEvent[any]{CloudEventHeader: event.CloudEventHeader, Data: latLong}, err
}

// handleError logs an error and returns a Fiber error with the given message.
func handleError(err error, logger *zerolog.Logger, message string) error {
	logger.Error().Err(err).Msg(message)
	return fiber.NewError(fiber.StatusInternalServerError, message)
}

// getFirstGWMeta retrieves the first gateway metadata from a list of Via events.
func getFirstGWMeta(vias []lorawan.Via) lorawan.GWMetadata {
	for _, via := range vias {
		if via.Metadata.GatewayID != "" {
			return via.Metadata
		}
	}
	return lorawan.GWMetadata{}
}

func getLatAndLong(signals []vss.Signal) (LatLongData, bool) {
	const notFound = 181.0 // invalid latitude and longitude value
	ret := LatLongData{Latitude: notFound, Longitude: notFound}

	for _, signal := range signals {
		if signal.Name == vss.FieldCurrentLocationLatitude {
			ret.Latitude = signal.ValueNumber
		} else if signal.Name == vss.FieldCurrentLocationLongitude {
			ret.Longitude = signal.ValueNumber
		}
	}
	if ret.Latitude == notFound || ret.Longitude == notFound {
		return ret, false
	}
	return ret, true
}

func distance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Radius of the Earth in kilometers
	dLat := (lat2 - lat1) * (math.Pi / 180)
	dLon := (lon2 - lon1) * (math.Pi / 180)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*(math.Pi/180))*math.Cos(lat2*(math.Pi/180))*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c * 0.621371 // Convert to miles
}

type LatLongData struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}
