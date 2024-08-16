// Package pom manages the POM (Proof of Movement) verifiable credential.
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
	"github.com/DIMO-Network/model-garage/pkg/twilio"
	"github.com/DIMO-Network/model-garage/pkg/vss"
	"github.com/DIMO-Network/model-garage/pkg/vss/convert"
	"github.com/DIMO-Network/shared"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const (
	autoPiManufacturer  = "AutoPi"
	hashDogManufacturer = "HashDog"
)

var errNoLocation = fmt.Errorf("no location data found")

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
	// get meta data about the vehilce
	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, tokenID)
	if err != nil {
		return handleError(err, &logger, "Failed to get vehicle info")
	}

	locations, err := s.getLocationForVehicle(ctx, vehicleInfo, &logger)
	if err != nil {
		return handleError(err, &logger, "Failed to get locations")
	}
	pomSubject := verifiable.POMSubject{
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress,
		RecordedBy:             "DIMO", //TODO: what should this be?
		Locations:              locations,
	}
	vc, err := s.issuer.CreatePOMVC(pomSubject, time.Now().Add(24*time.Hour))
	if err != nil {
		return handleError(err, &logger, "Failed to create POM VC")
	}
	fmt.Println(string(vc))
	return nil
}

func (s *Service) getLocationForVehicle(ctx context.Context, vehicleInfo *models.VehicleInfo, logger *zerolog.Logger) ([]verifiable.Location, error) {
	// first try and get the location from the aftermarket devices associated with the vehicle

	// stable sort the paired devices for more consistent results.
	// sort the paired devices to have the aftermarket devices first then. If neither is aftermarket, sort by type lexicographically.
	slices.SortStableFunc(vehicleInfo.PairedDevices, pairedDeviceSorterfunc)
	// slices.Reverse(vehicleInfo.PairedDevices)
	for i := range vehicleInfo.PairedDevices {
		locations, err := s.getLocationsForDevice(ctx, vehicleInfo.TokenID, vehicleInfo.PairedDevices[i], logger)
		if err == nil {
			return locations, nil
		}
		if !errors.Is(err, errNoLocation) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no location data found for vehicle")
}

func (s *Service) getLocationsForDevice(ctx context.Context, vehicleTokenID uint32, device models.PairedDevice, logger *zerolog.Logger) ([]verifiable.Location, error) {
	if device.Type == models.DeviceTypeAftermarket {
		switch device.ManufacturerName {
		case autoPiManufacturer:
			return pullAutoPiEvents(ctx, s.connectivityRepo, device.IMEI, time.Now())
		case hashDogManufacturer:
			return pullMacaronEvents(ctx, s.connectivityRepo, device.Address, time.Now())
		default:
			return nil, fmt.Errorf("unsupported aftermarket Manufacture: %s", device.ManufacturerName)
		}
	}
	return pullStatusEvents(ctx, s.connectivityRepo, vehicleTokenID, time.Now())
}

// handleError logs an error and returns a Fiber error with the given message.
func handleError(err error, logger *zerolog.Logger, message string) error {
	logger.Error().Err(err).Msg(message)
	return fiber.NewError(fiber.StatusInternalServerError, message)
}

func pairedDeviceSorterfunc(a, b models.PairedDevice) int {
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

func pullAutoPiEvents(ctx context.Context, repo ConnectivityRepo, deviceIMEI string, startTime time.Time) ([]verifiable.Location, error) {
	limit := 10
	before := startTime
	weekAgo := startTime.Add(-7 * 24 * time.Hour)
	var prevEvent twilio.ConnectionEvent
	for time.Since(startTime) < 7*24*time.Hour {
		events, err := repo.GetAutoPiEvents(ctx, deviceIMEI, weekAgo, before, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get AutoPi events: %w", err)
		}
		if len(events) == 0 {
			break
		}
		for _, rawEvent := range events {
			var cloudevent shared.CloudEvent[twilio.ConnectionEvent]
			if err := json.Unmarshal(rawEvent, &cloudevent); err != nil {
				return nil, fmt.Errorf("failed to unmarshal AutoPi event: %w", err)
			}
			event := cloudevent.Data
			if event.Location != nil && event.Location.CellID != "" {
				if prevEvent.Location != nil && prevEvent.Location.CellID != event.Location.CellID {
					return []verifiable.Location{
						{
							LocationType:  "cell_id",
							LocationValue: verifiable.CellID{CellID: prevEvent.Location.CellID},
							Timestamp:     prevEvent.Timestamp,
						},
						{
							LocationType:  "cell_id",
							LocationValue: verifiable.CellID{CellID: event.Location.CellID},
							Timestamp:     event.Timestamp,
						},
					}, nil
				}
				prevEvent = event
			}
			before = event.Timestamp
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}

	return nil, errNoLocation
}

func pullStatusEvents(ctx context.Context, repo ConnectivityRepo, vehicleTokenID uint32, startTime time.Time) ([]verifiable.Location, error) {
	limit := 10
	before := startTime
	weekAgo := startTime.Add(-7 * 24 * time.Hour)
	var prevLatitude, prevLongitude float64

	prevSource := ""
	for weekAgo.Before(before) {
		events, err := repo.GetStatusEvents(ctx, vehicleTokenID, weekAgo, before, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get status events: %w", err)
		}
		if len(events) == 0 {
			break
		}
		for _, event := range events {
			signals, err := convert.SignalsFromPayload(context.Background(), nil, event)
			if err != nil {
				return nil, fmt.Errorf("failed to convert signals: %w", err)
			}
			if len(signals) == 0 {
				continue
			}
			source := signals[0].Source
			if source != prevSource {
				fmt.Println("source", source)
				prevSource = source
			}

			// if signals[0].Source ==
			var curLatitude, curLongitude float64
			timeStamp := time.Time{}
			for _, signal := range signals {
				if signal.Name == vss.FieldCurrentLocationLatitude {
					curLatitude = signal.ValueNumber
					timeStamp = signal.Timestamp
				} else if signal.Name == vss.FieldCurrentLocationLongitude {
					curLongitude = signal.ValueNumber
				}
			}
			if curLatitude == 0 || curLongitude == 0 {
				continue
			}
			if prevLatitude == 0 && prevLongitude == 0 {
				prevLatitude = curLatitude
				prevLongitude = curLongitude
				continue
			}
			if prevLatitude != curLatitude && prevLongitude != curLongitude {
				fmt.Println("new location", curLatitude, curLongitude)
			}
			dist := distance(prevLatitude, prevLongitude, curLatitude, curLongitude)
			if dist > 0.5 {
				return []verifiable.Location{
					{
						LocationType:  "lat_lng",
						LocationValue: verifiable.LatLng{Latitude: prevLatitude, Longitude: prevLongitude},
						Timestamp:     before,
					},
					{
						LocationType:  "lat_lng",
						LocationValue: verifiable.LatLng{Latitude: curLatitude, Longitude: curLongitude},
						Timestamp:     timeStamp,
					}}, nil
			}
			before = timeStamp
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}

	return nil, errNoLocation
}

func pullMacaronEvents(ctx context.Context, repo ConnectivityRepo, deviceAddr common.Address, startTime time.Time) ([]verifiable.Location, error) {
	limit := 10
	before := startTime
	weekAgo := startTime.Add(-7 * 24 * time.Hour)
	var prevGatewayID string

	for time.Since(startTime) < 7*24*time.Hour {
		events, err := repo.GetHashDogEvents(ctx, deviceAddr, weekAgo, before, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get Macaron events: %w", err)
		}
		if len(events) == 0 {
			break
		}

		for _, event := range events {
			var loc MacaronLocation
			if err := json.Unmarshal(event, &loc); err != nil {
				return nil, fmt.Errorf("failed to unmarshal Macaron event: %w", err)
			}
			if prevGatewayID != "" && prevGatewayID != loc.GatewayID {
				return []verifiable.Location{
					{
						LocationType:  "gateway_id",
						LocationValue: verifiable.GatewayID{GatewayID: prevGatewayID},
						Timestamp:     before,
					},
					{
						LocationType:  "gateway_id",
						LocationValue: verifiable.GatewayID{GatewayID: loc.GatewayID},
						Timestamp:     loc.Timestamp,
					}}, nil
			}
			prevGatewayID = loc.GatewayID
			before = loc.Timestamp
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}

	return nil, errNoLocation
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
