package models

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
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
	Address          common.Address `json:"address"`
	IMEI             string         `json:"imei"`
	Type             DeviceType     `json:"type"`
	ManufacturerName string         `json:"manufacturerName"`
}

// FingerprintMessage represents the fingerprint message containing VIN and timestamp.
type FingerprintMessage struct {
	Timestamp time.Time      `json:"time"`
	Subject   string         `json:"subject"`
	Data      map[string]any `json:"data"`
	Data64    *string        `json:"data_base64"`
}

// DecodedFingerprintData represents the decoded fingerprint data.
type DecodedFingerprintData struct {
	VIN       string    `json:"vin"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
}

// VehicleInfo contains information about a vehicle NFT
type VehicleInfo struct {
	TokenID       uint32
	PairedDevices []PairedDevice
	NameSlug      string
}
