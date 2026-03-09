package connection

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Use AES-GCM to encrypt the msg structure
// Input an unprocessed frame with unpadded payload
// Output an encrypted frame as byte slice with exploit header, hidden header and encrypted payload
func (sc *SecureConn) EncryptAll(msg *Msg) ([]byte, error) {
	// Get key state from epoch
	keyState, err := sc.GetEpochKey(msg.HeaderExploit.Epoch)
	if err != nil {
		return nil, fmt.Errorf("key not found for epoch %d: %w", msg.HeaderExploit.Epoch, err)
	}

	// Marshalling headers
	headerHiddenByte := msg.HeaderHidden.Marshal()
	headerExploitByte := msg.HeaderExploit.Marshal()

	// Encrypt hidden header with exploit header as AAD extra message
	hNonce := make([]byte, NonceSize)
	if _, err := rand.Read(hNonce); err != nil {
		return nil, err
	}
	hiddenEncrypted := keyState.headerAEAD.Seal(hNonce, hNonce, headerHiddenByte, headerExploitByte)

	// Encrypt payload with exploit header as AAD extra message
	pNonce := make([]byte, keyState.msgAEAD.NonceSize())
	if _, err := rand.Read(pNonce); err != nil {
		return nil, err
	}
	fullPayload, err := msg.getPaddedPayload()
	if err != nil {
		return nil, fmt.Errorf("get padded payload failed: %w", err)
	}

	payloadEncrypted := keyState.msgAEAD.Seal(pNonce, pNonce, fullPayload, headerExploitByte)
	if payloadEncrypted == nil {
		return nil, fmt.Errorf("encrypt payload failed")
	}

	// Concacting exploit header, hidden header and encrypted payload
	encryptedFrame := append(headerExploitByte, hiddenEncrypted...)
	encryptedFrame = append(encryptedFrame, payloadEncrypted...)

	return encryptedFrame, nil
}

// DecryptHeader Phase 1: Unmarshal exploit header and decrypt hidden header
// Input should be the fixed-size head portion of the frame: [ExploitHeader] + [H-Nonce + H-Cipher]
func (sc *SecureConn) DecryptHeader(headerBuffer []byte) (ex *MsgHeaderExploit, hi *MsgHeaderHidden, err error) {
	// 1. Unmarshal the plaintext Exploit Header
	ex = new(MsgHeaderExploit)
	if err := ex.Unmarshal(headerBuffer[:ExploitHeaderSize]); err != nil {
		return nil, nil, fmt.Errorf("unmarshal exploit header failed: %w", err)
	}

	// 2. Identify the crypto state
	keyState, err := sc.GetEpochKey(ex.Epoch)
	if err != nil {
		return nil, nil, fmt.Errorf("key not found for epoch %d, current epoch keys are: %v, message type is: %d, txCount is: %d", ex.Epoch, sc.keys, hi.MsgType, hi.TxCount)
	}

	// 3. Decrypt the Hidden Header using Exploit Header as AAD
	hStart := ExploitHeaderSize
	hEnd := hStart + AEADOverhead + HiddenHeaderSize
	if len(headerBuffer) < hEnd {
		return nil, nil, errors.New("header buffer too short")
	}

	hNonce := headerBuffer[hStart : hStart+NonceSize]
	hCiphertext := headerBuffer[hStart+NonceSize : hEnd]
	aad := headerBuffer[:ExploitHeaderSize]

	decrypted, err := keyState.headerAEAD.Open(nil, hNonce, hCiphertext, aad)

	if err != nil {
		return nil, nil, fmt.Errorf("hidden header auth failed (AAD mismatch): %w", err)
	}

	hi = new(MsgHeaderHidden)
	if err := hi.Unmarshal(decrypted); err != nil {
		return nil, nil, fmt.Errorf("unmarshal hidden header failed: %w", err)
	}

	return ex, hi, nil
}

// DecryptPayload Phase 2: Decrypt the variable-length payload and strip padding
// Input should be the ciphertext portion: [P-Nonce] + [P-Cipher]
func (sc *SecureConn) DecryptPayload(ex *MsgHeaderExploit, hi *MsgHeaderHidden, payloadBuffer []byte) ([]byte, error) {
	keyState, err := sc.GetEpochKey(ex.Epoch)
	if err != nil {
		return nil, fmt.Errorf("key not found for epoch %d: %w", ex.Epoch, err)
	}
	if len(payloadBuffer) < int(hi.CipherLen) {
		return nil, errors.New("payload buffer too short")
	}

	// 1. Decrypt the Payload using Exploit Header as AAD
	pNonce := payloadBuffer[:NonceSize]
	pCiphertext := payloadBuffer[NonceSize:]

	// Crucial: Use the same AAD (exploit header) for cross-authentication
	aad := ex.Marshal() // Or pass the original raw bytes if available

	decrypted, err := keyState.msgAEAD.Open(nil, pNonce, pCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("payload decryption failed: %w", err)
	}

	// 2. Strip padding based on PayloadLen in Hidden Header
	if int(hi.PayloadLen) > len(decrypted) {
		return nil, errors.New("invalid payload length: hidden header claims more than decrypted size")
	}

	return decrypted[:hi.PayloadLen], nil
}
