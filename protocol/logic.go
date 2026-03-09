package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// GenMsg1 generates the first message of the SIGMA-I handshake (Alice -> Bob).
func (s *Session) genMsg1() ([]byte, error) {
	// Choose Curve
	curve := ecdh.X25519()

	// Generate Ephemeral private key
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Get Ephemeral public key (x, g^x)
	s.ephemeralKey = priv
	// log.Println("sender's ephemeral public key:", s.ephemeralKey.PublicKey().Bytes())

	return s.ephemeralKey.PublicKey().Bytes(), nil
}

// ProcessMsg1 handles the first message (Bob receives Msg1).
// 1. Load data into RemotePub (g^x)
// 2. Compute shared secret with ecdh, and create MAC and Session key based on sharedSecret
func (s *Session) processMsg1(data []byte) error {
	// Load data into RemotePub (g^x)
	curve := ecdh.X25519()
	remotePubObj, err := curve.NewPublicKey(data)
	if err != nil {
		return fmt.Errorf("invalid remote public key: %w", err)
	}
	s.RemotePub = remotePubObj

	// Generate Ephemeral private key and set into ephemeralKey
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.ephemeralKey = priv

	// Compute shared secret with ecdh, and store it in sharedSecret
	sharedSecret, err := s.ephemeralKey.ECDH(remotePubObj)
	if err != nil {
		return fmt.Errorf("ecdh failed: %w", err)
	}
	copy(s.sharedSecret[:], sharedSecret)

	// Create MAC and Session key based on sharedSecret
	MACReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("MAC"))
	MACReader.Read(s.macKey[:])

	// Create GCM key based on sharedSecret
	GCMReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("GCM"))
	GCMReader.Read(s.gcmKey[:])

	SessionReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("session"))
	SessionReader.Read(s.encryptionKey[:])

	HeaderReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("header"))
	HeaderReader.Read(s.headerKey[:])

	return nil
}

// GenMsg2 generates the second message of the SIGMA-I handshake (Bob -> Alice).
func (s *Session) genMsg2(data []byte) ([]byte, error) {
	// Sign with key：\sigma B ←Sign(sk_B, gx (remote) || gy (local) )
	// With the previous knowledge that private key and public key is equal to 32.
	keyMsg := make([]byte, 64)
	copy(keyMsg[:32], s.RemotePub.Bytes())
	copy(keyMsg[32:], s.ephemeralKey.PublicKey().Bytes())
	sig, err := s.OwnCert.SignMsgWithPriv(keyMsg)
	if err != nil {
		return nil, fmt.Errorf("sign msg with priv failed: %w", err)
	}

	// Create MAC message: HMAC(K_MAC, certB)
	h := hmac.New(sha256.New, s.macKey[:])
	certBytes, err := s.OwnCert.Cert.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal own cert failed: %w", err)
	}
	// log.Println("cert bytes:", certBytes)

	h.Write(certBytes)

	mac := h.Sum(nil)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(certBytes)))

	payload := append(lenBuf, certBytes...)
	payload = append(payload, sig...)
	payload = append(payload, mac...)
	encryptedPayload, err := s.encryptGCM(payload)

	if err != nil {
		return nil, fmt.Errorf("encrypt payload failed: %w", err)
	}
	// Msg2: g^y || encryptedPayload
	pub := s.ephemeralKey.PublicKey().Bytes()
	msg2 := make([]byte, 0, len(pub)+len(encryptedPayload))
	msg2 = append(msg2, pub...)
	msg2 = append(msg2, encryptedPayload...)
	// log.Println("msg2:", msg2)
	return msg2, nil
}

// Process Msg 2
// 1. Generating session and mac key
// 2. Certfying MAC message and digital signature of CA
// 3. Certifying CA
func (s *Session) processMsg2(data []byte) error {
	// Upon receiving public key, computing shared secret
	curve := ecdh.X25519()
	remotePubObj, err := curve.NewPublicKey(data[:32])
	if err != nil {
		return fmt.Errorf("invalid remote public key: %w", err)
	}
	s.RemotePub = remotePubObj

	sharedSecret, err := s.ephemeralKey.ECDH(remotePubObj)
	if err != nil {
		return fmt.Errorf("key exchange invalid: %w", err)
	}
	copy(s.sharedSecret[:], sharedSecret)

	// from shared secret derive mac key and gcm key
	// Create MAC and Session key based on sharedSecret
	MACReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("MAC"))
	MACReader.Read(s.macKey[:])

	// Create GCM key based on sharedSecret
	GCMReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("GCM"))
	GCMReader.Read(s.gcmKey[:])

	SessionReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("session"))
	SessionReader.Read(s.encryptionKey[:])

	HeaderReader := hkdf.New(sha256.New, s.sharedSecret[:], nil, []byte("header"))
	HeaderReader.Read(s.headerKey[:])

	// log.Println("===============Sender calling HandleMsg2AndReply===============")
	// log.Println("sender's ephemeral public key:", s.ephemeralKey.PublicKey().Bytes())
	// log.Println("sender's remote public key:", s.RemotePub.Bytes())
	// log.Println("sender's shared secret:", s.sharedSecret[:])
	// log.Println("sender's mac key:", s.macKey[:])
	// log.Println("sender's encryption key:", s.encryptionKey[:])
	// log.Println("sender's header key:", s.headerKey[:])
	// log.Println("=================================================================")

	// Decrypt and read payload.
	encryptedPayload := data[32:]
	plaintext, err := s.decryptGCM(encryptedPayload)
	if err != nil {
		return fmt.Errorf("decrypt payload failed: %w", err)
	}

	// Read certBytelen and certBytes from payload.
	certBytelen := binary.BigEndian.Uint32(plaintext[:4])
	certBytes := plaintext[4 : 4+certBytelen]
	sig := plaintext[4+certBytelen : 4+certBytelen+64]
	mac := plaintext[4+certBytelen+64:]

	// HMAC Verification certBytes with remote CA, by computing MAC(original CA' value, MAC key)
	h := hmac.New(sha256.New, s.macKey[:])
	h.Write(certBytes)
	expectedMac := h.Sum(nil)

	if !hmac.Equal(mac, expectedMac) {
		return fmt.Errorf("verify mac failed")
	}

	// Signature Verification with g^x (local) || g^y (remote)
	s.peerCert.Unmarshal(certBytes)
	keyMsg := make([]byte, 64)
	copy(keyMsg[32:], s.RemotePub.Bytes())
	copy(keyMsg, s.ephemeralKey.PublicKey().Bytes())

	success, err := s.peerCert.VerifyMsgWithPub(sig, keyMsg)
	if err != nil {
		return fmt.Errorf("verify msg with pub failed: %w", err)
	}

	if success == false {
		return fmt.Errorf("signature of g^x || g^y verification failed")
	}

	// CA verification
	success = s.peerCert.Verify(s.CAPubKey[:])
	if success == false {
		return fmt.Errorf("signature of CA verification failed")
	}

	s.State = SharedSecretEstablished

	return nil
}

// GenMsg2 generates the second message (Bob -> Alice).
// Contains g^y, encrypted {CertB, SigB(g^x, g^y), MAC(KB, IDB)}.
func (s *Session) genMsg3(data []byte) ([]byte, error) {
	// generate digital signature from B
	keyMsg := make([]byte, 64)
	copy(keyMsg[32:], s.RemotePub.Bytes())
	copy(keyMsg, s.ephemeralKey.PublicKey().Bytes())

	sig, err := s.OwnCert.SignMsgWithPriv(keyMsg)
	if err != nil {
		return nil, fmt.Errorf("sign msg with priv failed: %w", err)
	}

	// Create MAC message: HMAC(K_MAC, certA)
	h := hmac.New(sha256.New, s.macKey[:])
	certBytesA, err := s.OwnCert.Cert.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal own cert failed: %w", err)
	}
	h.Write(certBytesA)
	mac := h.Sum(nil)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(certBytesA)))
	payload := append(lenBuf, certBytesA...)
	payload = append(payload, sig...)
	payload = append(payload, mac...)

	encryptedPayload, err := s.encryptGCM(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt payload failed: %w", err)
	}

	return encryptedPayload, nil
}

// ProcessMsg3 handles the third message (Bob receives Msg3).
func (s *Session) processMsg3(data []byte) error {
	// Deserialized msg3: c_A, \sigma_A, \mu_A
	plaintext, err := s.decryptGCM(data)
	if err != nil {
		return fmt.Errorf("decrypt payload failed: %w", err)
	}

	// Read certBytelen and certBytes from payload.
	certBytelen := binary.BigEndian.Uint32(plaintext[:4])
	certBytes := plaintext[4 : 4+certBytelen]
	sig := plaintext[4+certBytelen : 4+certBytelen+64]
	mac := plaintext[4+certBytelen+64:]

	// HMAC Verification certBytes with CA.
	h := hmac.New(sha256.New, s.macKey[:])
	h.Write(certBytes)
	expectedMac := h.Sum(nil)

	// Verify MAC.
	if !hmac.Equal(mac, expectedMac) {
		return fmt.Errorf("verify mac failed")
	}

	// store remote byte in local
	s.peerCert.Unmarshal(certBytes)

	// Verify digital signature from A
	keyMsg := make([]byte, 64)
	copy(keyMsg, s.RemotePub.Bytes())
	copy(keyMsg[32:], s.ephemeralKey.PublicKey().Bytes())

	valid, err := s.peerCert.VerifyMsgWithPub(sig, keyMsg)
	if err != nil {
		return fmt.Errorf("verify sig failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("verify sig failed")
	}

	s.State = SharedSecretEstablished

	return nil
}

func (s *Session) encryptGCM(plaintext []byte) ([]byte, error) {
	// Implement GCM encryption using derived session key.
	block, err := aes.NewCipher(s.gcmKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm failed: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce failed: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (s *Session) decryptGCM(data []byte) ([]byte, error) {
	// Implement GCM decryption using derived session key.
	block, err := aes.NewCipher(s.gcmKey[:])
	if err != nil {
		return nil, fmt.Errorf("new cipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm failed: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt gcm failed: %w", err)
	}
	return plaintext, nil
}
