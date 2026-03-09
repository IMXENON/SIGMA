package protocol

import (
	"crypto/ecdh"
	"crypto_protocols/sigma/ca"
	"fmt"
)

// Identity holds the long-term identity of a node.
type Identity struct {
	CAPubKey [32]byte
	OwnCert  ca.LocalCA
}

type sessionState int

// sessionState represents the state of a SIGMA-I protocol session.
const (
	StateIdle sessionState = iota
	StateInitialized
	// Initiator 状态
	StateMsg1Sent
	StateMsg2Processed
	// Responder 状态
	StateMsg2Sent
	// 共同状态
	SharedSecretEstablished
	StateFailed
)

// Session holds the state for a single SIGMA-I protocol execution.
type Session struct {
	*Identity
	ephemeralKey  *ecdh.PrivateKey // Store information of x and g^x
	RemotePub     *ecdh.PublicKey  // received g^y
	sharedSecret  [32]byte         // (g^y)^x, same size as x25519SharedSecretSize
	macKey        [32]byte         // HKDF(SharedSecret || "MAC")
	gcmKey        [32]byte         // HKDF(SharedSecret || "GCM")
	encryptionKey [32]byte         // HKDF(SharedSecret || "session")
	headerKey     [32]byte         // HKDF(SharedSecret || "header")
	peerCert      ca.SimpleCert    // Bob's Cert
	State         sessionState
}

func NewSession(identity *Identity) *Session {
	return &Session{
		Identity: identity,
		State:    StateInitialized,
	}
}

// If state is ready, return the session key.
func (s *Session) RequestSessionKey() ([32]byte, error) {
	if s.StateEq(SharedSecretEstablished) {
		return s.encryptionKey, nil
	}
	return [32]byte{}, fmt.Errorf("session not ready, current state is: %d", s.GetState())
}

// If state is ready, return the header key.
func (s *Session) RequestHeaderKey() ([32]byte, error) {
	if s.StateEq(SharedSecretEstablished) {
		return s.headerKey, nil
	}
	return [32]byte{}, fmt.Errorf("session not ready, current state is: %d", s.GetState())
}

// SetState sets the state of the session.
func (s *Session) SetState(state sessionState) {
	s.State = state
}

// GetState returns the state of the session.
func (s *Session) GetState() sessionState {
	return s.State
}

// StateEq returns true if the session state is equal to the given state.
func (s *Session) StateEq(state sessionState) bool {
	return s.GetState() == state
}

// Get peer subject from peer certificate
func (s *Session) GetPeerSubject() string {
	return string(s.peerCert.Subject[:])
}

func (s *Session) Wipe() {
	s.ephemeralKey = nil
	s.RemotePub = nil
	s.sharedSecret = [32]byte{}
	s.macKey = [32]byte{}
	s.gcmKey = [32]byte{}
	s.encryptionKey = [32]byte{}
	s.headerKey = [32]byte{}
	s.peerCert = ca.SimpleCert{}
	s.State = StateIdle
}
