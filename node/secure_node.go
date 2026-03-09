package node

import (
	"crypto_protocols/sigma/connection"
	"crypto_protocols/sigma/protocol"
	"fmt"
	"sync"
)

type SecureNode struct {
	Identity protocol.Identity
	Port     string
	// Connection pool: Subject -> SecureConn
	peers    map[string]*connection.SecureConn
	PeersMu  sync.RWMutex
	IsActive bool
}

func NewSecureNode(id *protocol.Identity, port string) *SecureNode {
	return &SecureNode{
		Identity: *id,
		Port:     port,
		peers:    make(map[string]*connection.SecureConn),
	}
}

func (node *SecureNode) addPeer(subject string, conn *connection.SecureConn) {
	node.PeersMu.Lock()
	defer node.PeersMu.Unlock()
	node.peers[subject] = conn
}

func (node *SecureNode) getPeer(subject string) (*connection.SecureConn, error) {

	node.PeersMu.RLock()
	defer node.PeersMu.RUnlock()
	if len(subject) != 32 {
		subject = ProcessSubject(subject)
	}
	sc, ok := node.peers[subject]
	if !ok {
		return nil, fmt.Errorf("peer %s not found", subject)
	}
	return sc, nil
}
