package telemetryapi

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// locationSignals is the set of signal names whose value is a Location object
// rather than a scalar. They require a nested selection set in GraphQL queries.
var locationSignals = map[string]bool{
	"currentLocationCoordinates":            true,
	"currentLocationApproximateCoordinates": true,
}

// GenerateLatestSignalsQuery generates a GraphQL query for latest signals based on requested signal names.
func GenerateLatestSignalsQuery(signals []string) string {
	if len(signals) == 0 {
		// Return empty query if no signals requested
		return `query ($tokenId: Int!) { signalsLatest(tokenId: $tokenId) { lastSeen } }`
	}

	var builder strings.Builder
	_, _ = builder.WriteString(`query ($tokenId: Int!) {
	signalsLatest(tokenId: $tokenId) {
		lastSeen
`)
	for _, signal := range signals {
		if locationSignals[signal] {
			_, _ = fmt.Fprintf(&builder, "\t\t%s { timestamp value { latitude longitude hdop } }\n", signal)
		} else {
			_, _ = fmt.Fprintf(&builder, "\t\t%s { timestamp value }\n", signal)
		}
	}

	_, _ = builder.WriteString("\t}\n}")
	return builder.String()
}

// GenerateHistoricalQuery generates a GraphQL query for historical signals based on requested signal names.
func GenerateHistoricalQuery(signals []string) string {
	if len(signals) == 0 {
		// Return empty query if no signals requested
		return `query ($tokenId: Int!, $from: Time!, $to: Time!, $interval: String!) { signals(tokenId: $tokenId, from: $from, to: $to, interval: $interval) { timestamp } }`
	}

	var builder strings.Builder
	_, _ = builder.WriteString(`query ($tokenId: Int!, $from: Time!, $to: Time!, $interval: String!) {
	signals(tokenId: $tokenId, from: $from, to: $to, interval: $interval) {
		timestamp
`)

	for _, signal := range signals {
		if locationSignals[signal] {
			_, _ = fmt.Fprintf(&builder, "\t\t%s(agg:LAST) { latitude longitude hdop }\n", signal)
		} else {
			_, _ = fmt.Fprintf(&builder, "\t\t%s(agg:LAST)\n", signal)
		}
	}
	_, _ = builder.WriteString("\t}\n}")

	return builder.String()
}

// graphQLResponse represents the structure of the GraphQL response.
type graphQLResponse struct {
	Data   dataField      `json:"data"`
	Errors []graphQLError `json:"errors"`
}

// dataField represents the top-level data field in the GraphQL response.
type dataField struct {
	SignalsLatest *SignalCollection    `json:"signalsLatest"`
	Signals       []SignalAggregations `json:"signals"`
}

// SignalCollection represents the latest signals collection from telemetry API.
type SignalCollection struct {
	LastSeen                                time.Time       `json:"lastSeen"`
	CurrentLocationCoordinates              *SignalLocation `json:"currentLocationCoordinates"`
	CurrentLocationApproximateCoordinates   *SignalLocation `json:"currentLocationApproximateCoordinates"`
	PowertrainTransmissionTravelledDistance *SignalFloat    `json:"powertrainTransmissionTravelledDistance"`
	Speed                                   *SignalFloat    `json:"speed"`
	ObdDTCList                              *SignalString   `json:"obdDTCList"`
	ObdStatusDTCCount                       *SignalFloat    `json:"obdStatusDTCCount"`
	ChassisAxleRow1WheelLeftTirePressure    *SignalFloat    `json:"chassisAxleRow1WheelLeftTirePressure"`
	ChassisAxleRow1WheelRightTirePressure   *SignalFloat    `json:"chassisAxleRow1WheelRightTirePressure"`
	ChassisAxleRow2WheelLeftTirePressure    *SignalFloat    `json:"chassisAxleRow2WheelLeftTirePressure"`
	ChassisAxleRow2WheelRightTirePressure   *SignalFloat    `json:"chassisAxleRow2WheelRightTirePressure"`
}

// SignalAggregations represents historical signal aggregations.
type SignalAggregations struct {
	Timestamp                               time.Time `json:"timestamp"`
	CurrentLocationCoordinates              *Location `json:"currentLocationCoordinates"`
	CurrentLocationApproximateCoordinates   *Location `json:"currentLocationApproximateCoordinates"`
	PowertrainTransmissionTravelledDistance *float64  `json:"powertrainTransmissionTravelledDistance"`
	Speed                                   *float64  `json:"speed"`
	ObdDTCList                              *string   `json:"obdDTCList"`
	ObdStatusDTCCount                       *float64  `json:"obdStatusDTCCount"`
	ChassisAxleRow1WheelLeftTirePressure    *float64  `json:"chassisAxleRow1WheelLeftTirePressure"`
	ChassisAxleRow1WheelRightTirePressure   *float64  `json:"chassisAxleRow1WheelRightTirePressure"`
	ChassisAxleRow2WheelLeftTirePressure    *float64  `json:"chassisAxleRow2WheelLeftTirePressure"`
	ChassisAxleRow2WheelRightTirePressure   *float64  `json:"chassisAxleRow2WheelRightTirePressure"`
}

// SignalFloat represents a float signal with timestamp.
type SignalFloat struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// SignalString represents a string signal with timestamp.
type SignalString struct {
	Timestamp time.Time `json:"timestamp"`
	Value     string    `json:"value"`
}

// SignalLocation represents a location signal with timestamp.
type SignalLocation struct {
	Timestamp time.Time `json:"timestamp"`
	Value     Location  `json:"value"`
}

// Location is a WGS 84 coordinate as returned by the telemetry GraphQL API.
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	HDOP      float64 `json:"hdop"`
}

// Signal represents a telemetry signal (for backward compatibility).
type Signal struct {
	Name      string    `json:"name"`
	Value     any       `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}

// graphQLError represents an error returned from the GraphQL API.
type graphQLError struct {
	Message string `json:"message"`
}

// TelemetryHistoricalOptions represents options for querying telemetry data.
type TelemetryHistoricalOptions struct {
	TokenID   *big.Int  `json:"tokenId"`
	StartDate time.Time `json:"startDate,omitempty"`
	EndDate   time.Time `json:"endDate,omitempty"`
	Interval  string    `json:"interval,omitempty"`
	Signals   []string  `json:"signals,omitempty"`
}

type TelemetryLatestOptions struct {
	TokenID  *big.Int `json:"tokenId"`
	JWTToken string   `json:"jwtToken"`
	Signals  []string `json:"signals"`
}
