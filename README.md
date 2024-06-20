# attestation-api

Run `make`

## License

[Apache 2.0](LICENSE)

# VIN VC Eligibility Logic

### 1. Check if there is Currently a Valid VC for the NFT

- **Check Existing VCs for NFT**:
  - Query to determine if there is already a valid VC for the requesting NFT.
  - If a valid VC exists return it and end the process.

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
  - Verify that the VIN in the latest fingerprint messages from the paired device(s) matches each other.
  - **Use Latest Message as Source of Truth**:
    - If the VINs from the paired devices do not match, use the VIN from the latest fingerprint message as the source of truth.

### 6. Validate VIN Decodes Correctly

- **Decode and Validate VIN**:
  - Decode the VIN from the latest fingerprint message.
  - Ensure the VIN decodes to the same manufacturer, model, and year as per vehicle records.

### 7. Generate New VC

- **Create VIN VC**:
  - Generate a new VC for the NFT, including:
    - **VIN**: The Vehicle Identification Number.
    - **Issuance Date**: The timestamp of credential issuance.
    - **Expiration Date**: The timestamp indicating when the credential will expire.
    - **Issuer**: The entity issuing the VC.
    - **Proof**: Digital signature or cryptographic proof.
  - **Sign and Store VC**:
    - Ensure the VC is digitally signed to maintain integrity and authenticity.
    - Store the VC securely in the system.

### 8. Issue VC

- Return a query to be run on telemetry-api for VC retrieval
