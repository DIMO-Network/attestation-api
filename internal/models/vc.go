package models

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// LocationTypeCellID represents the cell ID location type.
	LocationTypeCellID = "cellId"
	// LocationTypeH3Cell represents the latitude/longitude location type.
	LocationTypeH3Cell = "h3Cell"
	// LocationTypeGatewayID represents the gateway ID location type.
	LocationTypeGatewayID = "gatewayId"
)

// POMSubject represents the subject of the Proof of Movement VC.
type POMSubject struct {
	ID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// RecordedBy is the entity that recorded the event.
	RecordedBy string     `json:"recordedBy,omitempty"`
	Locations  []Location `json:"locations"`
}

// Location represents a single location event with type, value, and timestamp.
type Location struct {
	LocationType  string        `json:"locationType"`
	LocationValue LocationValue `json:"locationValue"`
	Timestamp     time.Time     `json:"timestamp"`
}

// LocationValue represents a generic interface for location values.
type LocationValue interface {
	isLocationValue()
}

// CellID represents a cell ID location value.
type CellID struct {
	CellID string `json:"cellId"`
}

func (CellID) isLocationValue() {}

// H3Cell represents a latitude/longitude location value.
type H3Cell struct {
	CellID string `json:"h3CellId"`
}

func (H3Cell) isLocationValue() {}

// GatewayID represents a gateway ID location value.
type GatewayID struct {
	GatewayID string `json:"gatewayId"`
}

func (GatewayID) isLocationValue() {}

// UnmarshalJSON custom unmarshals a Location to handle the polymorphic LocationValue.
func (l *Location) UnmarshalJSON(data []byte) error {
	type Alias Location
	aux := &struct {
		LocationValue json.RawMessage `json:"locationValue"`
		*Alias
	}{
		Alias: (*Alias)(l),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch l.LocationType {
	case LocationTypeCellID:
		var cellID CellID
		if err := json.Unmarshal(aux.LocationValue, &cellID); err != nil {
			return err
		}
		l.LocationValue = cellID
	case LocationTypeH3Cell:
		var latLng H3Cell
		if err := json.Unmarshal(aux.LocationValue, &latLng); err != nil {
			return err
		}
		l.LocationValue = latLng
	case LocationTypeGatewayID:
		var gatewayID GatewayID
		if err := json.Unmarshal(aux.LocationValue, &gatewayID); err != nil {
			return err
		}
		l.LocationValue = gatewayID
	default:
		return fmt.Errorf("unknown location type: %s", l.LocationType)
	}

	return nil
}
