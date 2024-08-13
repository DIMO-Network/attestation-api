// Package pom manages the POM (Proof of Movement) verifiable credential.
// ### Steps for Creating a Proof of Movement VC

// 1. **Get Aftermarket Devices for a Vehicle**:

//    - Query the identity-API to retrieve the aftermarket devices associated with the vehicle.

// 2. **Device Data Retrieval**:

//    - **AutoPi**:
//      - Look up the device connectivity info in s3 using the device address.
//      - Continue to pull Twilio logs for the device using the address until two records with different `location.cell_id` values are found.
//    - **Smartcar or Tesla**:
//      - Pull status payloads until there is a change in latitude and longitude with a significant difference. (0.5 miles?)
//    - **Macaron**:
//      - Look up the device payloads in s3 using the device address.
//      - Continue to pull LoRaWAN logs for the device using the address until two records with different `via.[0].metadata.gatewayId` values are found.

// 3. **Create Proof of Movement VC**:

// - Create a new Proof of Movement VC that includes the times the vehicle was seen at each location (cell ID for AutoPi, latitude/longitude for Smartcar or Tesla, and gateway ID for Macaron).
package pom

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const (
	autoPiManufacturer  = "AutoPi"
	hashDogManufacturer = "HashDog"
)

type Service struct {
	logger                 zerolog.Logger
	identityAPI            IdentityAPI
	connectivityRepo       ConnectivityRepo
	vcRepo                 VCRepo
	issuer                 Issuer
	vehicleContractAddress string
}

// GeneratePOMVC generates a Proof of Movement VC.
func (s *Service) GeneratePOMVC(ctx context.Context, tokenID uint32) error {
	logger := s.logger.With().Uint32("vehicleTokenId", tokenID).Logger()
	// get meta data about the vehilce
	vehicleInfo, err := s.identityAPI.GetVehicleInfo(ctx, tokenID)
	if err != nil {
		return handleError(err, &logger, "Failed to get vehicle info")
	}

	locations, err := getLocation(ctx, vehicleInfo, &logger)
	if err != nil {
		return handleError(err, &logger, "Failed to get locations")
	}
	pomSubject := verifiable.POMSubject{
		VehicleTokenID:         tokenID,
		VehicleContractAddress: s.vehicleContractAddress,
		RecordedBy:             "DIMO", //TODO: what should this be?
		Locations:              locations,
	}
	s.issuer.CreatePOMVC(pomSubject, time.Now().Add(24*time.Hour))

	return nil
}

func getLocation(ctx context.Context, vehicleInfo *models.VehicleInfo, logger *zerolog.Logger) ([]verifiable.Location, error) {
	// first try and get the location from the aftermarket devices associated with the vehicle

	// stable sort the paired devices for more consistent results.
	// sort the paired devices to have the aftermarket devices first then. If neither is aftermarket, sort by type lexicographically.
	slices.SortStableFunc(vehicleInfo.PairedDevices, pairedDeviceSorterfunc)
	for i := range vehicleInfo.PairedDevices {
		locations, err := getLocations(ctx, vehicleInfo.TokenID, vehicleInfo.PairedDevices[i], logger)
		if err != nil {
			return nil, err
		}
		return locations, nil

	}
	return nil, fmt.Errorf("no location data found for vehicle")
}

func getLocations(ctx context.Context, vehicleTokenID uint32, device models.PairedDevice, logger *zerolog.Logger) ([]verifiable.Location, error) {
	var repo ConnectivityRepo
	if device.Type == models.DeviceTypeAftermarket {
		switch device.ManufacturerName {
		case autoPiManufacturer:
			return pullAutoPiEvents(ctx, repo, device.IMEI, time.Now())
		case hashDogManufacturer:
			return pullMacaronEvents(ctx, repo, device.Address, time.Now())
		default:
			return nil, fmt.Errorf("unsupported device type: %s", device.Type)
		}
	}
	return pullStatusEvents(ctx, repo, vehicleTokenID, time.Now())
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
	after := startTime
	var prevLocation AutoPiLocation

	for time.Since(startTime) < 7*24*time.Hour {
		events, err := repo.GetAutoPiEvents(ctx, deviceIMEI, after, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get AutoPi events: %w", err)
		}

		for _, event := range events {
			var loc AutoPiLocation
			if err := json.Unmarshal(event, &loc); err != nil {
				return nil, fmt.Errorf("failed to unmarshal AutoPi event: %w", err)
			}
			if prevLocation.CellID != "" && prevLocation.CellID != loc.CellID {
				return []verifiable.Location{
					{
						LocationType:  "cell_id",
						LocationValue: verifiable.CellID{CellID: prevLocation.CellID},
						Timestamp:     prevLocation.Timestamp,
					},
					{
						LocationType:  "cell_id",
						LocationValue: verifiable.CellID{CellID: loc.CellID},
						Timestamp:     loc.Timestamp,
					}}, nil
			}
			prevLocation = loc
			after = loc.Timestamp
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}

	return nil, fmt.Errorf("no location change detected within a week")
}

func pullStatusEvents(ctx context.Context, repo ConnectivityRepo, vehicleTokenID uint32, startTime time.Time) ([]verifiable.Location, error) {
	limit := 10
	after := startTime
	var prevLatitude, prevLongitude float64

	for time.Since(startTime) < 7*24*time.Hour {
		events, err := repo.GetStatusEvents(ctx, vehicleTokenID, after, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get status events: %w", err)
		}

		for _, event := range events {
			var loc StatusLocation
			if err := json.Unmarshal(event, &loc); err != nil {
				return nil, fmt.Errorf("failed to unmarshal status event: %w", err)
			}
			if prevLatitude != 0 && prevLongitude != 0 && distance(prevLatitude, prevLongitude, loc.Latitude, loc.Longitude) > 0.5 {
				return []verifiable.Location{
					{
						LocationType:  "lat_lng",
						LocationValue: verifiable.LatLng{Latitude: prevLatitude, Longitude: prevLongitude},
						Timestamp:     after,
					},
					{
						LocationType:  "lat_lng",
						LocationValue: verifiable.LatLng{Latitude: loc.Latitude, Longitude: loc.Longitude},
						Timestamp:     loc.Timestamp,
					}}, nil
			}
			prevLatitude = loc.Latitude
			prevLongitude = loc.Longitude
			after = loc.Timestamp
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}

	return nil, fmt.Errorf("no location change detected within a week")
}

func pullMacaronEvents(ctx context.Context, repo ConnectivityRepo, deviceAddr common.Address, startTime time.Time) ([]verifiable.Location, error) {
	limit := 10
	after := startTime
	var prevGatewayID string

	for time.Since(startTime) < 7*24*time.Hour {
		events, err := repo.GetHashDogEvents(ctx, deviceAddr, after, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get Macaron events: %w", err)
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
						Timestamp:     after,
					},
					{
						LocationType:  "gateway_id",
						LocationValue: verifiable.GatewayID{GatewayID: loc.GatewayID},
						Timestamp:     loc.Timestamp,
					}}, nil
			}
			prevGatewayID = loc.GatewayID
			after = loc.Timestamp
		}

		limit = int(math.Min(1000, float64(limit*2)))
	}

	return nil, fmt.Errorf("no location change detected within a week")
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
