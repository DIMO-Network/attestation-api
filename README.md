# attestation-api

![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
[![GoDoc](https://godoc.org/github.com/DIMO-Network/attestation-api?status.svg)](https://godoc.org/github.com/DIMO-Network/attestation-api)
[![Go Report Card](https://goreportcard.com/badge/github.com/DIMO-Network/attestation-api)](https://goreportcard.com/report/github.com/DIMO-Network/attestation-api)

## License

[Apache 2.0](LICENSE)

Run `make help`

```shell
Specify a subcommand:

  test                 run tests
  lint                 run linter
  docker               build docker image
  tools-golangci-lint  install golangci-lint
  tools-swagger        install swagger tool
  tools-mockgen        install mockgen tool
  generate             run all file generation for the project
  swagger              generate swagger documentation
  go-generate          run go generate
```

## Devlopment

Running this locally requires the following services to be running:

- [identity-api](https://github.com/DIMO-Network/identity-api/)
- [token-exchange-api](https://github.com/DIMO-Network/token-exchange-api)
- [device-definition-api](https://github.com/DIMO-Network/device-definitions-api)
- clickhouse connection
- s3 connection

# VIN VC Eligibility Logic

### 1. Check if there is Currently a Valid VC for the NFT

- **Check Existing VCs for NFT**:
  - Query to determine if there is already a valid VC for the requesting NFT.
  - If a valid VC exists return a success response with the VC query.

### 2. Get the Paired Device(s) for the NFT

- **Retrieve Device(s) from Identity API**:
  - Call the `identity-api` to get the device(s) (aftermarket and/or synthetic) associated with the NFT.
  - Ensure the devices are correctly paired with the NFT.

### 4. Get the Latest Fingerprint Messages for the Paired Device(s)

- **Retrieve Fingerprint Messages**:

  - Obtain the latest fingerprint messages for the paired device(s) of the NFT.

- **No Fingerprint Messages**:
  - If there are no fingerprint messages for the paired device(s), return an error.

### 5. Validate VIN for Each Paired Device Matches

- **Ensure VIN Consistency**:
  - **Use Latest Message as Source of Truth**:
    - If the VINs from the paired devices do not match, use the VIN from the latest fingerprint message as the source of truth.

### 6. Validate VIN Decodes Correctly

- **Decode and Validate VIN**:
  - Decode the VIN from the latest fingerprint message.
  - Ensure the VIN decodes to the same manufacturer, model, and year as per vehicle record in identity-api.

### 7. Generate New VC

- Generate a new VC for the tokenId and VIN
- Store the VC in s3

### 8. Return VC Query

- Return a query to be run on telemetry-api for VC retrieval
