package telemetryapi

import "encoding/json"

// GraphQL query to fetch latest telemetry signals.
const latestSignalsQuery = `
	query ($tokenId: Int!) {
		signalsLatest(tokenId: $tokenId) {
			lastSeen
			currentLocationLatitude { timestamp value }
			currentLocationLongitude { timestamp value }
			currentLocationApproximateLatitude { timestamp value }
			currentLocationApproximateLongitude { timestamp value }
			powertrainTransmissionTravelledDistance { timestamp value }
			speed { timestamp value }
			obdDTCList { timestamp value }
			obdStatusDTCCount { timestamp value }
			chassisAxleRow1WheelLeftTirePressure { timestamp value }
			chassisAxleRow1WheelRightTirePressure { timestamp value }
			chassisAxleRow2WheelLeftTirePressure { timestamp value }
			chassisAxleRow2WheelRightTirePressure { timestamp value }
		}
	}
`

// GraphQL query to fetch historical telemetry data.
const historicalQuery = `
	query ($tokenId: Int!, $from: String!, $to: String!) {
		signals(tokenId: $tokenId, from: $from, to: $to) {
			timestamp
			currentLocationLatitude
			currentLocationLongitude
			currentLocationApproximateLatitude
			currentLocationApproximateLongitude
			powertrainTransmissionTravelledDistance
			speed
			obdDTCList
			obdStatusDTCCount
			chassisAxleRow1WheelLeftTirePressure
			chassisAxleRow1WheelRightTirePressure
			chassisAxleRow2WheelLeftTirePressure
			chassisAxleRow2WheelRightTirePressure
		}
	}
`

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
	LastSeen                                string        `json:"lastSeen"`
	CurrentLocationLatitude                 *SignalFloat  `json:"currentLocationLatitude"`
	CurrentLocationLongitude                *SignalFloat  `json:"currentLocationLongitude"`
	CurrentLocationApproximateLatitude      *SignalFloat  `json:"currentLocationApproximateLatitude"`
	CurrentLocationApproximateLongitude     *SignalFloat  `json:"currentLocationApproximateLongitude"`
	PowertrainTransmissionTravelledDistance *SignalFloat  `json:"powertrainTransmissionTravelledDistance"`
	Speed                                   *SignalFloat  `json:"speed"`
	ObdDTCList                              *SignalString `json:"obdDTCList"`
	ObdStatusDTCCount                       *SignalFloat  `json:"obdStatusDTCCount"`
	ChassisAxleRow1WheelLeftTirePressure    *SignalFloat  `json:"chassisAxleRow1WheelLeftTirePressure"`
	ChassisAxleRow1WheelRightTirePressure   *SignalFloat  `json:"chassisAxleRow1WheelRightTirePressure"`
	ChassisAxleRow2WheelLeftTirePressure    *SignalFloat  `json:"chassisAxleRow2WheelLeftTirePressure"`
	ChassisAxleRow2WheelRightTirePressure   *SignalFloat  `json:"chassisAxleRow2WheelRightTirePressure"`
}

// SignalAggregations represents historical signal aggregations.
type SignalAggregations struct {
	Timestamp                               string   `json:"timestamp"`
	CurrentLocationLatitude                 *float64 `json:"currentLocationLatitude"`
	CurrentLocationLongitude                *float64 `json:"currentLocationLongitude"`
	CurrentLocationApproximateLatitude      *float64 `json:"currentLocationApproximateLatitude"`
	CurrentLocationApproximateLongitude     *float64 `json:"currentLocationApproximateLongitude"`
	PowertrainTransmissionTravelledDistance *float64 `json:"powertrainTransmissionTravelledDistance"`
	Speed                                   *float64 `json:"speed"`
	ObdDTCList                              *string  `json:"obdDTCList"`
	ObdStatusDTCCount                       *float64 `json:"obdStatusDTCCount"`
	ChassisAxleRow1WheelLeftTirePressure    *float64 `json:"chassisAxleRow1WheelLeftTirePressure"`
	ChassisAxleRow1WheelRightTirePressure   *float64 `json:"chassisAxleRow1WheelRightTirePressure"`
	ChassisAxleRow2WheelLeftTirePressure    *float64 `json:"chassisAxleRow2WheelLeftTirePressure"`
	ChassisAxleRow2WheelRightTirePressure   *float64 `json:"chassisAxleRow2WheelRightTirePressure"`
}

// SignalFloat represents a float signal with timestamp.
type SignalFloat struct {
	Timestamp string  `json:"timestamp"`
	Value     float64 `json:"value"`
}

// SignalString represents a string signal with timestamp.
type SignalString struct {
	Timestamp string `json:"timestamp"`
	Value     string `json:"value"`
}

// TelemetryRecord represents a telemetry data record (for backward compatibility).
type TelemetryRecord struct {
	Timestamp string   `json:"timestamp"`
	Source    string   `json:"source"`
	Signals   []Signal `json:"signals"`
}

// Signal represents a telemetry signal (for backward compatibility).
type Signal struct {
	Name      string      `json:"name"`
	Value     interface{} `json:"value"`
	Timestamp string      `json:"timestamp"`
}

// graphQLError represents an error returned from the GraphQL API.
type graphQLError struct {
	Message string `json:"message"`
}

// TelemetryQueryOptions represents options for querying telemetry data.
type TelemetryQueryOptions struct {
	TokenID   int      `json:"tokenId"`
	StartDate string   `json:"startDate,omitempty"`
	EndDate   string   `json:"endDate,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	Signals   []string `json:"signals,omitempty"`
}

// nullableString is a string that can interpret "null" as nil.
type nullableString struct {
	value *string
}

// UnmarshalJSON unmarshals a nullableString.
func (n *nullableString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		n.value = nil
		return nil
	}
	return json.Unmarshal(data, &n.value)
}
