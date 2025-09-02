package types

import (
	"encoding/json"
	"fmt"
	"time"
)

// Credential represents a verifiable credential.
type Credential struct {
	ValidFrom         time.Time       `json:"validFrom,omitempty"`
	ValidTo           time.Time       `json:"validTo,omitempty"`
	CredentialSubject json.RawMessage `json:"credentialSubject,omitempty"`
}

// VINSubject represents the subject of the VIN verifiable credential.
type VINSubject struct {
	VehicleDID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// VehicleIdentificationNumber is the VIN of the vehicle.
	VehicleIdentificationNumber string `json:"vehicleIdentificationNumber,omitempty"`
	// RecordedBy is the entity that recorded the VIN.
	RecordedBy string `json:"recordedBy,omitempty"`
	// RecordedAt is the time the VIN was recorded.
	RecordedAt time.Time `json:"recordedAt,omitempty"`
	// CountryCode that VIN belongs to.
	CountryCode string `json:"countryCode,omitempty"`
}

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

// VehiclePositionVCSubject represents the subject of the VehiclePositionVC.
type VehiclePositionVCSubject struct {
	VehicleDID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// RecordedBy is the entity that recorded the location.
	RecordedBy string `json:"recordedBy,omitempty"`
	// Location is the location data.
	Location Location `json:"location"`
	// RequestedTimestamp is the timestamp that was requested.
	RequestedTimestamp time.Time `json:"requestedTimestamp"`
}

// TimeRange represents a time range.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// OdometerStatementVCSubject represents the subject of the OdometerStatementVC.
type OdometerStatementVCSubject struct {
	VehicleDID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// RecordedBy is the entity that recorded the odometer reading.
	RecordedBy string `json:"recordedBy,omitempty"`
	// OdometerReading is the odometer value.
	OdometerReading OdometerReading `json:"odometerReading"`
	// RequestedTimestamp is the timestamp that was requested (if any).
	RequestedTimestamp *time.Time `json:"requestedTimestamp,omitempty"`
}

// OdometerReading represents an odometer reading with metadata.
type OdometerReading struct {
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"` // "km" or "miles"
	Timestamp time.Time `json:"timestamp"`
}

// VehicleHealthVCSubject represents the subject of the VehicleHealthVC.
type VehicleHealthVCSubject struct {
	VehicleDID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// RecordedBy is the entity that recorded the health data.
	RecordedBy string `json:"recordedBy,omitempty"`
	// HealthStatus contains the vehicle health information.
	HealthStatus VehicleHealthStatus `json:"healthStatus"`
	// SearchedTimeRange is the time range that was searched.
	SearchedTimeRange TimeRange `json:"searchedTimeRange"`
}

// VehicleHealthStatus represents the health status of a vehicle.
type VehicleHealthStatus struct {
	// DTCs contains diagnostic trouble codes found.
	DTCs []DiagnosticTroubleCode `json:"dtcs"`
	// TirePressure contains tire pressure readings.
	TirePressure *TirePressureStatus `json:"tirePressure,omitempty"`
	// HealthScore is an overall health score (0-100).
	HealthScore int `json:"healthScore"`
	// IsHealthy indicates if the vehicle is considered healthy.
	IsHealthy bool `json:"isHealthy"`
	// LastUpdated is when this health status was last updated.
	LastUpdated time.Time `json:"lastUpdated"`
}

// DiagnosticTroubleCode represents a DTC.
type DiagnosticTroubleCode struct {
	Code        string    `json:"code"`
	Description string    `json:"description,omitempty"`
	Severity    string    `json:"severity"` // "info", "warning", "critical"
	Timestamp   time.Time `json:"timestamp"`
}

// TirePressureStatus represents tire pressure readings.
type TirePressureStatus struct {
	FrontLeft  *float64  `json:"frontLeft,omitempty"`
	FrontRight *float64  `json:"frontRight,omitempty"`
	RearLeft   *float64  `json:"rearLeft,omitempty"`
	RearRight  *float64  `json:"rearRight,omitempty"`
	Unit       string    `json:"unit"` // "psi" or "kpa"
	IsNormal   bool      `json:"isNormal"`
	Timestamp  time.Time `json:"timestamp"`
}
