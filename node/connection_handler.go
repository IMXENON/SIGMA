package node

import (
	"crypto_protocols/sigma/connection"
	"fmt"
)

var footprint = 0

func (node *SecureNode) RegisterConnection(conn *connection.SecureConn) {
	node.PeersMu.Lock()
	defer node.PeersMu.Unlock()
	node.peers[conn.GetRemoteSubject()] = conn
}

// Hooker: Process unregistering and closing connection
func (node *SecureNode) UnregisterConnection(conn *connection.SecureConn) {
	node.PeersMu.Lock()
	defer node.PeersMu.Unlock()
	conn.Close()
	delete(node.peers, conn.GetRemoteSubject())
}

// startSender manages the interactive CLI for encrypted messaging.
func (n *SecureNode) sendToPeer(targetSubject string, message []byte) error {

	// 1. Route: Find the connection by Subject
	sConn, err := n.getPeer(targetSubject)
	if err != nil {
		return fmt.Errorf("Error: %v\n", err)
	}

	// TODO: to comment out the code
	fmt.Printf("Sending to %s: %s\n", targetSubject, string(message))

	// Check Connection State
	if sConn == nil {
		fmt.Printf("Error: No active secure session with [%s]\n", targetSubject)
		return fmt.Errorf("Error: No active secure session with [%s]\n", targetSubject)
	}

	// Pack, Encrypt & Send the message with interface
	// Note: WriteEnc should handle Nonce internally
	err = sConn.WriteEnc(connection.MsgTypeData, message)
	if err != nil {
		fmt.Printf("Send Failed: %v\n", err)
		return fmt.Errorf("Send Failed: %v\n", err)
	}

	// Check whether the txCount exceeds the maximum limit,
	// For initiator
	// 		If exceeds, set the state into ConnStateInitiatingHandshake immediately, trying to refeeshs
	// 		raise an error if the message type is MsgTypeData initiating another handshake
	// 		txCount increment here
	if sConn.IsRequireHandshakeStart(sConn.GetTxCount()) {
		// Calling handshake logic
		// fmt.Println("Handshake should start by listening")
		sConn.RefreshHandshakeInit(&n.Identity)
	}
	// For responder
	return nil
}

// StartReceiver begins a concurrent loop to listen for encrypted messages.
func (n *SecureNode) StartReceiver(sc *connection.SecureConn) {
	// Hooker: Unregister the connection and close the connection
	defer n.UnregisterConnection(sc)

	// remoteSub is stored during handshake certificate verification
	remoteSub := sc.GetRemoteSubject()

	for {
		// ReadEnc handles decryption and integrity checking (AEAD)
		// Passing nil/empty slice if ReadEnc handles network IO internally
		// There will be several situations that reader will return error:
		// 1. Connection closed by peer (including handshake phase and established phase (actively close))
		// 2. Connection lost due to network issue
		// 3. Decryption failed (e.g., tampered message or header)
		// No matter how the error occurs, we should close the connection
		// for sc.GetState() != connection.ConnStateEstablished {
		// }
		msg, err := sc.ReadEnc()
		if err != nil {
			fmt.Printf("\n[System] Connection with %s lost: %v\n> ", remoteSub, err)
			return
		}
		// Handle message type
		switch msg.HeaderHidden.MsgType {
		case connection.MsgTypeData:
			// Process the message payload, accepting message data from all modes (except for closed connection)
			if sc.StateEq(connection.ConnStateClosed) {
				fmt.Printf("\n[From %s]: Connection not in established state, message dropped\n> ", remoteSub)
				return
			}
			// Print the message payload in stdio, other logic can be added here
			// TODO: uncomment the code
			fmt.Printf("\n[From %s]: %s\n> ", remoteSub, string(msg.GetOriginalPayload()))
			// Check whether the session require refreshing key
			if sc.IsRequireHandshakeStart(msg.HeaderHidden.TxCount) {
				// Calling handshake logic
				sc.RefreshHandshakeInit(&n.Identity)
			}
			// Check whether the epoch require update for initiator
			if sc.Role == connection.RoleInitiator && sc.StateEq(connection.ConnStateWaitingForConfirm) {
				sc.EpochEqAndSet(msg.HeaderExploit.Epoch)
			}

		case connection.MsgTypeRefreshMsg1:
			// Process refresh message 1
			err := sc.CaseProcessTypeMsg1(msg, &n.Identity)
			if err != nil {
				fmt.Printf("\n[From %s]: RefreshMsg1 processing failed: %v\n> ", remoteSub, err)
				return
			}
		case connection.MsgTypeRefreshMsg2:
			// Process refresh message 2
			err := sc.CaseProcessTypeMsg2(msg)
			if err != nil {
				fmt.Printf("\n[From %s]: RefreshMsg2 processing failed: %v\n> ", remoteSub, err)
				return
			}
		case connection.MsgTypeRefreshMsg3:
			// Process refresh message 3
			err := sc.CaseProcessTypeMsg3(msg)
			if err != nil {
				fmt.Printf("\n[From %s]: RefreshMsg3 processing failed: %v\n> ", remoteSub, err)
				return
			}
		default:
			// Handle other message types
			fmt.Printf("\n[From %s]: Unknown message type %d\n> ", remoteSub, msg.HeaderHidden.MsgType)
			return

		}
	}
}
