package ca_server

import (
	"crypto/ed25519"
	"crypto_protocols/sigma/ca"
	"encoding/hex"
	"errors"
)

var (
	caPrivKey ed25519.PrivateKey
	caPubKey  ed25519.PublicKey
)

func init() {
	privHex := "74510531206b418d8eebaf7b675021d1aa3a4a556dcbd7263847c74dbe05504bd7043b20f237013e70d43004f554c58693015fbdd724b356a5ee33568ee4bba7"
	pubHex := "d7043b20f237013e70d43004f554c58693015fbdd724b356a5ee33568ee4bba7"

	pBytes, _ := hex.DecodeString(privHex)
	caPrivKey = ed25519.PrivateKey(pBytes)

	pbBytes, _ := hex.DecodeString(pubHex)
	caPubKey = ed25519.PublicKey(pbBytes)
}

// Receive a public key from applyer, and return a SimpleCert
func HandleCAApplyRequest(applyerPubKey ed25519.PublicKey, applyerSubject []byte) (ca.SimpleCert, error) {
	// 1. Verify Subject is in 32 bytes
	if len(applyerSubject) > 32 {
		return ca.SimpleCert{}, errors.New("invalid subject")
	}

	var subjectArray [32]byte
	copy(subjectArray[:], applyerSubject)

	var pubKeyArray [32]byte
	copy(pubKeyArray[:], applyerPubKey)

	// 2. Generating Certificate
	cert := ca.SimpleCert{
		Subject: subjectArray,
		PubKey:  pubKeyArray,
	}

	err := cert.Sign(ed25519.PrivateKey(caPrivKey))
	if err != nil {
		return ca.SimpleCert{}, err
	}
	// 3. Return Certificate
	return cert, nil
}

func HandleCAVerificationRequest(cert ca.SimpleCert) (bool, error) {
	// 1. Verify Simplecert Valid
	if cert.Subject == [32]byte{} || cert.PubKey == [32]byte{} {
		return false, errors.New("invalid certificate")
	}
	// 2. Verify Certificate
	if !cert.Verify(ed25519.PublicKey(caPubKey)) {
		return false, errors.New("invalid certificate")
	}
	// 3. Return verification result
	return true, nil
}
