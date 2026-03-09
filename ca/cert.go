package ca

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// SimpleCert represents a simplified certificate structure.
// Subject: 32 bytes
// PubKey: 32 bytes
// Sig: 64 bytes
type SimpleCert struct {
	Subject [32]byte
	PubKey  [32]byte
	Sig     [64]byte
}

type LocalCA struct {
	privKey ed25519.PrivateKey
	Cert    SimpleCert
}

// CA interface defines the behavior for a Certificate Authority.
type CA interface {
	Sign(cert *SimpleCert) error
	Verify(cert *SimpleCert) bool
	SignMsgWithPriv(msg []byte) ([]byte, error)
}

// Marshal converts the SimpleCert into a custom binary TLV format.
// Format: [Type (1 byte)] [Length (2 bytes)] [Value]
func (c *SimpleCert) Marshal() ([]byte, error) {
	// Implement custom binary TLV serialization.
	buffer := new(bytes.Buffer)
	// len最多为2字节，也就是value字段只能存放(0～（2^16-1）)字节
	// 检查长度是否合法，将长度转为byte(int16)，
	writeTLV := func(buf *bytes.Buffer, t uint8, value []byte) {
		buf.WriteByte(t)
		// 检查value长度
		val_len := len(value)
		if len(value) > 0xFFFF {
			panic(fmt.Sprintf("value length %d exceeds max 0xFFFF", len(value)))
		}
		len_buf := make([]byte, 2)
		binary.BigEndian.PutUint16(len_buf, uint16(val_len))
		buf.Write(len_buf)
		buf.Write(value)
	}

	writeTLV(buffer, 0x01, c.Subject[:])
	writeTLV(buffer, 0x02, c.PubKey[:])
	writeTLV(buffer, 0x03, c.Sig[:])
	// Ensure it follows the Type-Length-Value pattern.
	return buffer.Bytes(), nil
}

// Unmarshal populates the SimpleCert from a custom binary TLV format.
func (c *SimpleCert) Unmarshal(data []byte) error {
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		// 读取type
		t, err := reader.ReadByte()
		if err != nil {
			return err
		}
		// 读取length
		var length uint16
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return err
		}
		// 读取value
		// 安全检查
		if int(length) > reader.Len() {
			return fmt.Errorf("value length %d exceeds remaining data %d", length, reader.Len())
		}

		value := make([]byte, length)
		_, err = reader.Read(value)
		if err != nil {
			return err
		}

		// 根据Type填充结构体
		switch t {
		case 0x01:
			copy(c.Subject[:], value)
		case 0x02:
			copy(c.PubKey[:], value)
		case 0x03:
			copy(c.Sig[:], value)
		default:
			return fmt.Errorf("unknown type %x", t)
		}
	}
	return nil
}

// Generate certificate‘s digital signature,
func (cert *SimpleCert) Sign(privKey ed25519.PrivateKey) error {
	if cert == nil {
		return fmt.Errorf("cert is nil")
	}
	// Clear Signature Field
	cert.Sig = [64]byte{}
	serialized_cert, err := cert.Marshal()
	if err != nil {
		return err
	}
	// Sign the serialized certificate
	signature := ed25519.Sign(privKey, serialized_cert)

	if len(signature) != 64 {
		return errors.New("invalid signature length")
	}

	copy(cert.Sig[:], signature)

	return nil
}

// Verify checks if the certificate's signature is valid using the CA's public key.
func (cert *SimpleCert) Verify(PubKey ed25519.PublicKey) bool {

	// Copy and clear signature to recover original value
	sig := [64]byte{}
	copy(sig[:], cert.Sig[:])
	cert.Sig = [64]byte{}

	// Recover the serialized databytes from the certificate
	serialized_cert, err := cert.Marshal()
	if err != nil || len(serialized_cert) == 0 {
		return false
	}

	// Recover certificates
	defer func() {
		copy(cert.Sig[:], sig[:])
	}()

	return ed25519.Verify(PubKey, serialized_cert, sig[:])
}

func (ca *LocalCA) PutPrivKey(privKey ed25519.PrivateKey) error {
	ca.privKey = privKey
	return nil
}

func NewLocalCA() *LocalCA {
	return &LocalCA{}
}

// SignMsgWithPriv signs a message using the CA's private key.
func (ca *LocalCA) SignMsgWithPriv(msg []byte) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("msg is nil")
	}
	// Sign the message
	return ed25519.Sign(ca.privKey, msg), nil
}

// VerifyMsgWithPriv verifies a message using the CA's private key.
func (c *SimpleCert) VerifyMsgWithPub(signature []byte, msg []byte) (bool, error) {
	if msg == nil || signature == nil {
		return false, fmt.Errorf("msg is nil")
	}
	// Verify the message
	return ed25519.Verify(c.PubKey[:], msg, signature), nil
}
