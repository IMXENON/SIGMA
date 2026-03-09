package config

import (
	"crypto/ed25519"
	"encoding/hex"
)

func GetCAPubKey() ed25519.PublicKey {
	pubHex := "d7043b20f237013e70d43004f554c58693015fbdd724b356a5ee33568ee4bba7"

	pbBytes, _ := hex.DecodeString(pubHex)
	return ed25519.PublicKey(pbBytes)
}
