package identity

import "encoding/json"

// GraphQL query to fetch paired devices.
const query = `
	query ($tokenId: Int!) {
		vehicle(tokenId: $tokenId) {
			aftermarketDevice {
				tokenId
				address
				imei
				manufacturer {
					name
				}
			}
			syntheticDevice {
				tokenId
				address
			}
			definition{
				id
			}
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
	Vehicle vehicleField `json:"vehicle"`
}

// vehicleField represents the vehicle field in the GraphQL response.
type vehicleField struct {
	AftermarketDevice *deviceResponse `json:"aftermarketDevice"`
	SyntheticDevice   *deviceResponse `json:"syntheticDevice"`
	Definition        *definitionResponse
}

// deviceResponse represents the structure of the device response.
type deviceResponse struct {
	TokenID      uint32       `json:"tokenId"`
	Address      string       `json:"address"`
	IMEI         string       `json:"imei"`
	Manufacturer manufacturer `json:"manufacturer"`
}
type manufacturer struct {
	Name string `json:"name"`
}

type definitionResponse struct {
	ID nullableString `json:"id"`
}

// graphQLError represents an error returned from the GraphQL API.
type graphQLError struct {
	Message string `json:"message"`
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
