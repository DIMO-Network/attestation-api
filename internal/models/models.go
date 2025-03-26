package models

import (
	"github.com/DIMO-Network/cloudevent"
)

// DeviceType represents the type of device.
type DeviceType string

const (
	// DeviceTypeAftermarket represents an aftermarket device.
	DeviceTypeAftermarket DeviceType = "aftermarket"
	// DeviceTypeSynthetic represents a synthetic device.
	DeviceTypeSynthetic DeviceType = "synthetic"
)

// PairedDevice represents a device paired with a token.
type PairedDevice struct {
	DID              cloudevent.NFTDID `json:"nftDid"`
	Type             DeviceType        `json:"type"`
	ManufacturerName string            `json:"manufacturerName"`

	// TODO remove legacy lookup fields once ingest is updated
	Address string `json:"address"`
	IMEI    string `json:"imei"`
}

// DecodedFingerprintData represents the decoded fingerprint data.
type DecodedFingerprintData struct {
	cloudevent.CloudEventHeader
	VIN string `json:"vin"`
}

// VehicleInfo contains information about a vehicle NFT.
type VehicleInfo struct {
	DID           cloudevent.NFTDID
	PairedDevices []PairedDevice
	NameSlug      string
}
