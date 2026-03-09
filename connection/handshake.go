package connection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto_protocols/sigma/protocol"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

func (c *SecureConn) send(data []byte) error {
	length := uint32(len(data))
	buf := make([]byte, 4+len(data))

	binary.BigEndian.PutUint32(buf[:4], length)
	copy(buf[4:], data)

	_, err := c.RawConn.Write(buf)
	return err
}

func (c *SecureConn) recv() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.RawConn, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	data := make([]byte, length)

	if _, err := io.ReadFull(c.RawConn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (c *SecureConn) HandshakeAsInitiator(identity *protocol.Identity) error {
	// Generating Msg1
	c.RawConn.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.RawConn.SetDeadline(time.Time{})

	c.SetState(ConnStateHandshaking)

	session := protocol.NewSession(identity)
	c.Session = session

	msg1, err := c.Session.GenMsg1()
	if err != nil {
		c.Close()
		return fmt.Errorf("gen msg1 failed: %w", err)
	}

	// Sending Msg1

	if err := c.send(msg1); err != nil {
		c.Close()
		return fmt.Errorf("sending msg1 failed: %w", err)
	}

	// Receiving Msg2
	msg2, err := c.recv()
	if err != nil {
		c.Close()
		return fmt.Errorf("recving msg2 failed: %w", err)
	}

	// Processing Msg2
	// fmt.Println("Initiator: processing msg2")
	msg3, err := c.Session.HandleMsg2AndReply(msg2)
	if err != nil {
		c.Close()
		return fmt.Errorf("processing msg2 failed: %w", err)
	}

	// Sending Msg3

	if err := c.send(msg3); err != nil {
		c.Close()
		return fmt.Errorf("sending msg3 failed: %w", err)
	}

	return nil
}

func (c *SecureConn) HandshakeAsResponder(identity *protocol.Identity) error {
	// Generating Msg2
	c.RawConn.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.RawConn.SetDeadline(time.Time{})

	c.SetState(ConnStateHandshaking)
	session := protocol.NewSession(identity)
	c.Session = session

	// Upon receiving msg1, process and return msg2

	msg1, err := c.recv()
	if err != nil {
		c.SetState(ConnStateClosed)
		return fmt.Errorf("recving msg1 failed: %w", err)
	}

	msg2, err := c.Session.HandleMsg1AndReply(msg1)
	if err != nil {
		c.SetState(ConnStateClosed)
		return fmt.Errorf("processing msg1 failed: %w", err)
	}

	if err := c.send(msg2); err != nil {
		c.SetState(ConnStateClosed)
		return fmt.Errorf("sending msg2 failed: %w", err)
	}

	// Receiving Msg3

	msg3, err := c.recv()
	if err != nil {
		c.SetState(ConnStateClosed)
		return fmt.Errorf("recving msg3 failed: %w", err)
	}

	// Processing Msg3

	if err := c.Session.HandleMsg3(msg3); err != nil {
		c.SetState(ConnStateClosed)
		return fmt.Errorf("processing msg3 failed: %w", err)
	}

	c.SetState(ConnStateEstablished)

	return nil
}

func (c *SecureConn) FinalizeHandshake(epoch uint16) error {

	// Iniialize GCM
	// set session key

	// pring debug information: shared key
	sharedKey, err := c.Session.RequestSessionKey()

	if err != nil {
		return fmt.Errorf("request session key failed: %w", err)
	}
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return fmt.Errorf("new cipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm failed: %w", err)
	}

	// set header key
	headerKey, err := c.Session.RequestHeaderKey()
	if err != nil {
		return fmt.Errorf("request header key failed: %w", err)
	}
	headerBlock, err := aes.NewCipher(headerKey[:])
	if err != nil {
		return fmt.Errorf("new cipher failed: %w", err)
	}
	headerGCM, err := cipher.NewGCM(headerBlock)
	if err != nil {
		return fmt.Errorf("new gcm failed: %w", err)
	}

	// Assume epoch is initialized to 0
	AEADkey := &AEADkey{
		msgAEAD:    gcm,
		headerAEAD: headerGCM,
	}
	c.SetEpochKey(epoch, AEADkey)

	if err != nil {
		return fmt.Errorf("request session key failed: %w", err)
	}

	// Set remote subject
	c.SetRemoteSubjectFromSession()

	// Set session to nil
	c.WipeSession()

	return nil
}
