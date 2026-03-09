package connection

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	CipherMaxSize  = 1 << 16
	PaddedSize     = 1 << 4
	RandomMaxSize  = 1 << 8
	MessageMaxSize = CipherMaxSize - TagSize - PaddedSize - RandomMaxSize
)

// Given message, packing it into Msg type with a header and compute random padding size
// It's msg structure's responsibility to perform random padding (written in headers.go)
// Packing of other fields of Header can be added here
func (sc *SecureConn) PackMsg(msgType MsgType, payload []byte) (*Msg, error) {
	// Encrypt the payload
	pLen := len(payload)
	if pLen > MessageMaxSize {
		return nil, fmt.Errorf("payload size %d exceeds max size %d", len(payload), MessageMaxSize)
	}

	// Compute the padded length
	var rLen uint16
	rBuf := make([]byte, 2)
	if _, err := rand.Read(rBuf); err != nil {
		return nil, fmt.Errorf("generate random pad length failed: %w", err)
	}
	maxPossible := min(MessageMaxSize-pLen, RandomMaxSize)
	if maxPossible > 0 {
		rLen = binary.BigEndian.Uint16(rBuf) % uint16(maxPossible)
	}
	cLen := pLen + PaddedSize + int(rLen)

	// Packing the message headers
	HeaderHidden := NewMsgHeaderHidden(pLen, cLen, sc.TxCountIncr(), msgType)
	HeaderExploit := NewMsgHeaderExploit(0x1, sc.GetEpoch())

	msg := &Msg{
		HeaderHidden:  HeaderHidden,
		HeaderExploit: HeaderExploit,
		Payload:       payload,
	}

	return msg, nil
}

// Unpack Message from the msg header, unpadding the payload given the information from header
// Process of other fields of Header can be added here
func (sc *SecureConn) UnpackMsg(msg *Msg) (*Msg, error) {
	// Unpadding the payload
	pLen := int(msg.HeaderHidden.PayloadLen)
	if pLen > len(msg.Payload) {
		return nil, fmt.Errorf("invalid payload length: hidden header claims more than decrypted size")
	}
	msg.Payload = msg.Payload[:pLen]

	return msg, nil
}

// Process header and encrypt payload, increase txCount
func (sc *SecureConn) WriteEnc(msgType MsgType, payload []byte) error {
	// Packing into msg
	msg, err := sc.PackMsg(msgType, payload)
	if err != nil {
		return fmt.Errorf("pack msg failed: %w", err)
	}

	// Encrypt all into a message
	encryptedFrame, err := sc.EncryptAll(msg)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	// Send trough TCP connection
	_, err = sc.RawConn.Write(encryptedFrame)
	if err != nil {
		return fmt.Errorf("write encrypted frame failed: %w", err)
	}

	return nil
}

func (sc *SecureConn) ReadEnc() (*Msg, error) {
	// Packing Header
	headerBuffer := make([]byte, ExploitHeaderSize+AEADOverhead+HiddenHeaderSize)

	if _, err := io.ReadFull(sc.RawConn, headerBuffer); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("Connection Closed: %w", err)
		} else {
			return nil, fmt.Errorf("read header failed: %w", err)
		}
	}
	ex, hi, err := sc.DecryptHeader(headerBuffer)
	// DEBUG: Trace mode
	// sc.TraceRecv(ex)

	if err != nil {
		return nil, fmt.Errorf("decrypt header failed: %w", err)
	}

	payloadBuffer := make([]byte, hi.CipherLen)
	if _, err := io.ReadFull(sc.RawConn, payloadBuffer); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("Connection Closed: %w", err)
		} else {
			return nil, fmt.Errorf("read cipher failed: %w", err)
		}
	}

	decryptedMsg, err := sc.DecryptPayload(ex, hi, payloadBuffer)
	if err != nil {
		return nil, fmt.Errorf("decrypt msg failed: %w", err)
	}

	message := &Msg{
		HeaderHidden:  hi,
		HeaderExploit: ex,
		Payload:       decryptedMsg,
	}

	message, err = sc.UnpackMsg(message)
	if err != nil {
		return nil, fmt.Errorf("unpack msg failed: %w", err)
	}

	return message, nil
}
