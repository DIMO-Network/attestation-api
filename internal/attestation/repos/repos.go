package repos

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

var subjectLenth = 40

// AddressToString converts an address to a string for legacy subject encoding.
func AddressToString(addr common.Address) string {
	return common.Address(addr).Hex()[2:]
}

// TokenIDToString converts a token ID to a string for legacy subject encoding.
func TokenIDToString(tokenID uint32) string {
	return fmt.Sprintf("T%0*d", subjectLenth-1, tokenID)
}

// IMEIToString converts an IMEI string to a string for legacy subject encoding.
func IMEIToString(imei string) string {
	return fmt.Sprintf("IMEI%0*s", subjectLenth-4, imei)
}

// ref returns a pointer to the value passed in.
func Ref[T any](val T) *T {
	return &val
}
