package connection

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type MsgType uint8

const (
	MsgTypeHello MsgType = iota + 1
	MsgTypeData
	MsgTypeHeartbeat
	MsgTypeRefresh
	MsgTypeClose
	MsgTypeRefreshMsg1
	MsgTypeRefreshMsg2
	MsgTypeRefreshMsg3
)

const (
	HiddenHeaderSize  = 8 // CipherLen(2) + PayloadLen(2) + TxCount(2) + MsgType(1) + Reserved(1)
	ExploitHeaderSize = 3 // Version(1) + Epoch(2)
	TagSize           = 16
	NonceSize         = 12
	AEADOverhead      = TagSize + NonceSize
)

// MsgHeaderHidden 存放加密后的信息，包括 TxCount 和 MsgType
type MsgHeaderHidden struct {
	CipherLen  uint16
	PayloadLen uint16
	TxCount    uint16
	MsgType    MsgType
	Reserved   uint8
}

// MsgHeaderExploit 存放明文可认证的头部信息
type MsgHeaderExploit struct {
	Version uint8
	Epoch   uint16
}

// Msg 是加密消息对象
type Msg struct {
	HeaderHidden  *MsgHeaderHidden
	HeaderExploit *MsgHeaderExploit
	Payload       []byte
}

// -------------------- Marshal / Unmarshal --------------------

// Hidden header: CipherLen(2) | PayloadLen(2) | TxCount(2) | MsgType(1) | Reserved(1)
func (h *MsgHeaderHidden) Marshal() []byte {
	buf := make([]byte, HiddenHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], h.CipherLen)
	binary.BigEndian.PutUint16(buf[2:4], h.PayloadLen)
	binary.BigEndian.PutUint16(buf[4:6], h.TxCount)
	buf[6] = uint8(h.MsgType)
	buf[7] = h.Reserved
	return buf
}

func (h *MsgHeaderHidden) Unmarshal(data []byte) error {
	if len(data) != HiddenHeaderSize {
		return fmt.Errorf("invalid hidden header size: %d", len(data))
	}
	h.CipherLen = binary.BigEndian.Uint16(data[0:2])
	h.PayloadLen = binary.BigEndian.Uint16(data[2:4])
	h.TxCount = binary.BigEndian.Uint16(data[4:6])
	h.MsgType = MsgType(data[6])
	h.Reserved = data[7]
	return nil
}

// Exploit header: Version(1) | Epoch(2)
func (h *MsgHeaderExploit) Marshal() []byte {
	buf := make([]byte, ExploitHeaderSize)
	buf[0] = h.Version
	binary.BigEndian.PutUint16(buf[1:3], h.Epoch)
	return buf
}

func (h *MsgHeaderExploit) Unmarshal(data []byte) error {
	if len(data) != ExploitHeaderSize {
		return fmt.Errorf("invalid exploit header size: %d", len(data))
	}
	h.Version = data[0]
	h.Epoch = binary.BigEndian.Uint16(data[1:3])
	return nil
}

// -------------------- Helpers --------------------

func NewMsgHeaderHidden(plainPayloadLen int, paddedPayloadLen int, tx uint16, msgType MsgType) *MsgHeaderHidden {
	return &MsgHeaderHidden{
		CipherLen:  uint16(paddedPayloadLen + AEADOverhead),
		PayloadLen: uint16(plainPayloadLen),
		TxCount:    tx,
		MsgType:    msgType,
		Reserved:   0,
	}
}

func NewMsgHeaderExploit(version uint8, epoch uint16) *MsgHeaderExploit {
	return &MsgHeaderExploit{
		Version: version,
		Epoch:   epoch,
	}
}

// getPaddedPayload 填充 payload 并返回加密前的明文
func (msg *Msg) getPaddedPayload() ([]byte, error) {
	fullLen := int(msg.HeaderHidden.CipherLen) - AEADOverhead
	fullPlaintext := make([]byte, fullLen)

	// 拷贝原始 payload
	copy(fullPlaintext[:msg.HeaderHidden.PayloadLen], msg.Payload)

	// 剩余部分填充随机数
	if _, err := rand.Read(fullPlaintext[msg.HeaderHidden.PayloadLen:]); err != nil {
		return nil, fmt.Errorf("generate padding failed: %w", err)
	}
	return fullPlaintext, nil
}

// GetOriginalPayload 返回原始 payload，去掉 padding
func (msg *Msg) GetOriginalPayload() []byte {
	if len(msg.Payload) == int(msg.HeaderHidden.PayloadLen) {
		return msg.Payload
	}
	return msg.Payload[:msg.HeaderHidden.PayloadLen]
}
