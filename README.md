# attestation-api

Run `make`

## License

[Apache 2.0](LICENSE)

# VIN VC Eligibility Logic

## Constraints

1. **Each Vehicle has a VIN**.
2. **Each Vehicle can be associated with one or more NFTs**.
3. **Only one of the Vehicle NFTs can have a valid VC**.
4. **For an NFT to get a VC, it must be paired to a device**.
5. **Each vehicle has either an aftermarket device and/or a synthetic device associated with it**.
6. **Aftermarket devices and synthetic devices return fingerprint messages that contain the associated VIN**.
7. **Fingerprint messages contain the VIN of the vehicle they are physically assigned to**.

## Eligibility Logic

### 1. Get the Paired Device(s) for the NFT

- **Retrieve Device(s) from Identity API**:
  - Call the `identity-api` to get the device(s) (aftermarket and/or synthetic) associated with the NFT.
  - Ensure the devices are correctly paired with the NFT.

### 2. Revoke Existing VC for Paired Device(s) that are not for the NFT

- **Check Existing VCs for Paired Devices**:
  - Query to check if there is a currently valid VC for the Paired Device(s) associated with any other NFT.
  - **Revoke if Necessary**: If a valid VC is found for the Paired Device(s) and the NFT in the VC is not the same as the requesting NFT, revoke it to ensure no more than one valid VC per device.

### 3. Get the Latest Fingerprint Messages for the Paired Device(s)

- **Retrieve Fingerprint Messages**:
  - Obtain the latest fingerprint messages for the paired device(s) of the NFT.

### 4. Validate VIN for Each Paired Device Matches

- **Ensure VIN Consistency**:
  - Verify that the VIN in the latest fingerprint messages from the paired device(s) matches each other.
  - **Use Latest Message as Source of Truth**:
    - If the VINs from the paired devices do not match, use the VIN from the latest fingerprint message as the source of truth.

### 5. Validate VIN Decodes Correctly

- **Decode and Validate VIN**:
  - Decode the VIN from the latest fingerprint message.
  - Ensure the VIN decodes to the same manufacturer, model, and year as per vehicle records.

### 6. Revoke Existing VC that Uses the Same VIN

- **Check Existing VCs for VIN**:
  - Query to check if there is a currently valid VC for the VIN associated with any other NFT.
  - **Revoke if Necessary**: If a valid VC is found for the same VIN but linked to a different NFT, revoke it to prevent duplicate VCs for the VIN.
  - **Hash-Based Check**: Use a hash of the VIN to avoid storing the VIN directly in an index, ensuring privacy and data protection.

### 7. Check if there is Currently a Valid VC for the NFT

- **Check Existing VCs for NFT**:
  - Query to determine if there is already a valid VC for the requesting NFT.
  - **Revoke if Necessary**: If a valid VC exists for the NFT, revoke it to maintain only one valid VC per NFT.

### 8. Revoke Existing VC if No Paired Devices Found

- **Check Device Pairing**:
  - If the NFT is not paired to any device, revoke any existing VC for the NFT.
  - This ensures that VCs are only issued and remain valid for NFTs with proper device pairing.

### 9. Generate New VC

- **Create VIN VC**:
  - Generate a new VC for the NFT, including:
    - **VIN**: The Vehicle Identification Number.
    - **Issuance Date**: The timestamp of credential issuance.
    - **Expiration Date**: The timestamp indicating when the credential will expire.
    - **Issuer**: The entity issuing the VC.
    - **Proof**: Digital signature or cryptographic proof.
    - **Metadata**: Additional relevant information such as vehicle data and device associations. (NFT ID, Aftermarket Device ID, Synthetic Device ID, etc.)
  - **Sign and Store VC**:
    - Ensure the VC is digitally signed to maintain integrity and authenticity.
    - Store the VC securely in the system.

### 10. Issue VC

- **Issue to NFT**:
  - Issue the newly created VC to the requesting NFT.
  - **Update Records**: Update the system records to reflect the association of the VC with the NFT.
  - Ensure that the system recognizes the newly issued VC as the valid credential for the NFT.

## Conclusion

This logic ensures that all constraints are effectively addressed:

- Each vehicle's VIN is validated and confirmed.
- Each vehicle can be associated with multiple NFTs.
- Only one valid VC exists per VIN and per NFT at any time.
- An NFT must be paired to a device to receive a VC, and this pairing is verified.
- Discrepancies between device messages are resolved using the latest fingerprint message.
