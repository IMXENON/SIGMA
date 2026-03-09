package connection

import (
	"crypto/cipher"
	"crypto_protocols/sigma/protocol"
	"fmt"
	"net"
	"sync"
)

type ConnState int

const (
	ConnStateInit ConnState = iota
	ConnStateHandshaking
	// Only for initiatior's state
	ConnStateWaitingForConfirm
	ConnStateEstablished
	ConnStateRefreshing
	ConnStateClosed
)

type Role int

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

type SecureConn struct {
	RawConn       net.Conn          // TCP
	Session       *protocol.Session // Context of handshaking
	Port          string            // Local port
	Address       string            // Local address
	State         ConnState
	remoteAddr    string
	remoteSubject string
	mu            sync.RWMutex
	closeOnce     sync.Once
	Role
	txCount uint16
	epoch   uint16
	keys    map[uint16]*AEADkey // Map of epoch to AEAD keys

}

type AEADkey struct {
	msgAEAD    cipher.AEAD
	headerAEAD cipher.AEAD
}

const CtxMessageLimit = 5
const EpochBufferSize uint16 = 2

func NewSecureConn(conn net.Conn, port, address string, role Role) *SecureConn {
	return &SecureConn{
		RawConn:    conn,
		Session:    nil,
		Port:       port,
		Address:    address,
		State:      ConnStateInit,
		remoteAddr: conn.RemoteAddr().String(),
		keys:       make(map[uint16]*AEADkey),
		Role:       role,
		epoch:      0,
		txCount:    0,
	}
}

func (c *SecureConn) SetState(s ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.State = s
}

func (c *SecureConn) SecureSetState(s ConnState) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.State == s {
		return false
	}
	c.State = s
	return true
}

func (c *SecureConn) StateEq(s ConnState) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.State == s
}

func (c *SecureConn) GetState() ConnState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.State
}

// Explicitly Wipe sensitive field
func (c *SecureConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if !c.SecureSetState(ConnStateClosed) {
			return
		}
		// Wipe message and header AEAD
		c.WipeSession()
		c.Session = nil
		c.keys = nil
		err = c.RawConn.Close()
	})
	return err
}

func (c *SecureConn) GetRemoteSubject() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.remoteSubject
}

func (c *SecureConn) WipeSession() {
	if c.Session == nil {
		return
	}
	c.Session.Wipe()

}

// sConn.GetTxCount() implementaiton
func (c *SecureConn) GetTxCount() uint16 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.txCount
}

// return current txCount and increment it
func (c *SecureConn) TxCountIncr() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.txCount++ }()
	return c.txCount
}

func (c *SecureConn) GetKeysFromEpoch(epoch uint16) (*AEADkey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[epoch]
	if !ok {
		return nil, fmt.Errorf("epoch %d not found", epoch)
	}
	return key, nil
}

// SetKeysFromEpoch sets the AEAD keys for the given epoch.
func (c *SecureConn) SetKeysFromEpoch(epoch uint16, key *AEADkey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[epoch] = key
}

func (c *SecureConn) clearKeys(epoch uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := range c.keys {
		diff := (epoch - e) % 65535
		if diff > EpochBufferSize {
			delete(c.keys, e)
		}
	}
}

func (c *SecureConn) GetEpoch() uint16 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epoch
}
func (c *SecureConn) GetNextEpoch() uint16 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return (c.epoch + 1) % 65535
}

func (c *SecureConn) EpochIncr() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.epoch = (c.epoch + 1) % 65535
	c.txCount = 0
	return c.epoch
}

func (c *SecureConn) SetEpoch(epoch uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch = epoch
}

// If state is established, check if tx count exceeds the limit
// If exceeds the limit, set the state into handshaking, return true, else return false
// Otherwise, when state is not established (Refreshing or not exceeds), return false
func (c *SecureConn) IsRequireHandshakeStart(txCount uint16) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Protecting Initiator: In case several handshake
	if txCount >= CtxMessageLimit && c.State == ConnStateEstablished && c.Role == RoleInitiator && c.txCount > 0 {
		c.State = ConnStateHandshaking
		return true
	}
	return false
}

func (c *SecureConn) StateEqAndSet(seq ConnState, sset ConnState) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.State == seq {
		c.State = sset
		return true
	}
	return false
}

// Receive a new message with an epoch, if the epoch is larger than current epoch, set the new received epoch into current epoch
// Clear keys here, we assume the epoch is a ring (wrap around under 65536)
func (c *SecureConn) EpochEqAndSet(epoch uint16) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	diff := (epoch - c.epoch) % 65535
	if diff < EpochBufferSize && diff > 0 {
		c.epoch = epoch
		c.txCount = 0

		for e := range c.keys {

			if (epoch-e)%65535 > EpochBufferSize {
				delete(c.keys, e)
			}
		}
		c.State = ConnStateEstablished

		return true
	}
	return false
}

func (c *SecureConn) SetRemoteSubjectFromSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteSubject = c.Session.GetPeerSubject()
}

func (c *SecureConn) SetEpochKey(epoch uint16, key *AEADkey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[epoch] = key
}
func (c *SecureConn) GetEpochKey(epoch uint16) (*AEADkey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ok := c.keys[epoch]
	if !ok {
		return nil, fmt.Errorf("epoch %d not found", epoch)
	}
	return key, nil
}
