package models

import "time"

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
	TokenID uint32     `json:"token_id"`
	Type    DeviceType `json:"type"`
}

// FingerprintMessage represents the fingerprint message containing VIN and timestamp.
type FingerprintMessage struct {
	VIN       string    `json:"vin"`
	Timestamp time.Time `json:"timestamp"`
}
