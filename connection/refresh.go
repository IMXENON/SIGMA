package connection

import (
	"crypto_protocols/sigma/protocol"
	"fmt"
	"time"
)

// It's sendToPeer's responsibility to check whether to send msg1 to the peer.
// Sending encrypted msg1 with type msg1

func (c *SecureConn) RefreshHandshakeInit(identity *protocol.Identity) error {
	// Setting deadline for msg1 sending
	c.RawConn.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.RawConn.SetDeadline(time.Time{})
	// Initiate new session
	session := protocol.NewSession(identity)
	c.Session = session
	// generate and encrypt message 1
	msg1, err := c.Session.GenMsg1()
	if err != nil {
		return err
	}
	err = c.WriteEnc(MsgTypeRefreshMsg1, msg1)
	if err != nil {
		return fmt.Errorf("failed to write encrypted msg1: %w", err)
	}
	return nil
}

// The program logic is quite similar to protocol.HandleMsg1AndReply()
func (c *SecureConn) CaseProcessTypeMsg1(msg *Msg, identity *protocol.Identity) error {
	// Check connection state
	if !c.StateEqAndSet(ConnStateEstablished, ConnStateHandshaking) || c.Role != RoleResponder {
		return fmt.Errorf("connection not in msg1 processed state")
	}

	// Set state and Initiate session
	session := protocol.NewSession(identity)
	c.Session = session

	// Process msg1
	msg2, err := c.Session.HandleMsg1AndReply(msg.GetOriginalPayload())
	if err != nil {
		return fmt.Errorf("failed to handle msg1: %w", err)
	}
	// Set state and send msg2
	err = c.WriteEnc(MsgTypeRefreshMsg2, msg2)
	if err != nil {
		return fmt.Errorf("failed to write encrypted msg2: %w", err)
	}
	return nil
}

// Initiator process msg2
func (c *SecureConn) CaseProcessTypeMsg2(msg *Msg) error {
	// Check connection state
	if !c.StateEq(ConnStateHandshaking) || !c.Session.StateEq(protocol.StateMsg1Sent) || c.Role != RoleInitiator {
		return fmt.Errorf("connection not in msg2 processed state")
	}

	// Process msg2
	msg3, err := c.Session.HandleMsg2AndReply(msg.GetOriginalPayload())
	if err != nil {
		return fmt.Errorf("failed to handle msg2: %w", err)
	}
	// Established, call finalize handshake, assuming the initialize epoch is 0,
	// Put behind sending to make sure it has been ready for a new epoch message receiving
	// Session shouldn't be wiped before replying
	// // TODO: MUST be commented, since leak session key!!!!
	// if c.Role == RoleInitiator {
	// 	fmt.Printf("=== Initiator's epoch has been set to: %d ===\n", c.GetEpoch())
	// 	k, _ := c.Session.RequestSessionKey()
	// 	fmt.Printf("Initiator's session key: %x\n", k)
	// }

	err = c.FinalizeHandshake(msg.HeaderExploit.Epoch + 1)

	if err != nil {
		return fmt.Errorf("failed to finalize handshake: %w", err)
	}

	// Set state and send msg3
	err = c.WriteEnc(MsgTypeRefreshMsg3, msg3)

	if err != nil {
		return fmt.Errorf("failed to reply msg3: %w", err)
	}
	c.SetState(ConnStateWaitingForConfirm)
	if err != nil {
		return fmt.Errorf("failed to write encrypted msg3: %w", err)
	}

	return nil
}

func (c *SecureConn) CaseProcessTypeMsg3(msg *Msg) error {
	// Check connection state
	if !c.StateEq(ConnStateHandshaking) || !c.Session.StateEq(protocol.StateMsg2Sent) || c.Role != RoleResponder {
		return fmt.Errorf("connection not in msg3 processed state")
	}

	// Process msg3
	err := c.Session.HandleMsg3(msg.GetOriginalPayload())
	if err != nil {
		return fmt.Errorf("failed to handle msg3: %w", err)
	}

	// Established, call finalize handshake, assuming the initialize epoch is 0, increment epoch for the next message
	// Responder's epoch should be incremented after msg3 processed
	// Responder's state should be set to ConnStateEstablished
	// // TODO: MUST be commented, since leak session key!!!!
	// if c.Role == RoleResponder {
	// 	c.SetState(ConnStateEstablished)
	// 	fmt.Printf("=== Responder's epoch has been set to: %d ===\n", c.GetEpoch())
	// 	k, _ := c.Session.RequestSessionKey()
	// 	fmt.Printf("Responder's session key: %x\n", k)
	// 	c.SetState(ConnStateWaitingForConfirm)
	// }

	err = c.FinalizeHandshake(msg.HeaderExploit.Epoch + 1)
	if err != nil {
		return fmt.Errorf("failed to finalize handshake: %w", err)
	}

	c.EpochEqAndSet(msg.HeaderExploit.Epoch + 1)

	return nil
}
