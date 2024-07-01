package identity

// GraphQL query to fetch paired devices.
const query = `
	query ($tokenId: Int!) {
		vehicle(tokenId: $tokenId) {
			aftermarketDevice {
				address
			}
			syntheticDevice {
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
	Address string `json:"address"`
}

type definitionResponse struct {
	ID string `json:"id"`
}

// graphQLError represents an error returned from the GraphQL API.
type graphQLError struct {
	Message string `json:"message"`
}
