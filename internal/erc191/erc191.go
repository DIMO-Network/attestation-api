package erc191

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignMessage signs the message with the configured private key.
func SignMessage[T ~[]byte | ~string](message T, privateKey *ecdsa.PrivateKey) (string, error) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	sign := crypto.Keccak256Hash([]byte(msg))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)
	if err != nil {
		return "", err
	}

	signature[64] += 27 // Support old Ethereum format
	return "0x" + hex.EncodeToString(signature), nil
}
