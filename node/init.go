package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto_protocols/sigma/ca"
	"crypto_protocols/sigma/ca_server"
	"crypto_protocols/sigma/config"
	"crypto_protocols/sigma/protocol"
	"fmt"
	"log"
	"net/rpc"
)

// Initialize node's public key and private key
func InitNodeKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// Request for CA Certificate
func RequestCA(pubKey ed25519.PublicKey, subject []byte, url string, port string) (ca.SimpleCert, error) {
	// 1. connect to CA server
	conn, err := rpc.Dial("tcp", url+":"+port)
	if err != nil {
		return ca.SimpleCert{}, err
	}
	defer conn.Close()

	// 2. send CA application request
	req := ca_server.CAApplyRequest{
		ApplyerPubKey:  pubKey,
		ApplyerSubject: subject,
	}
	var reply ca.SimpleCert
	if err := conn.Call("CAApi.Apply", req, &reply); err != nil {
		return ca.SimpleCert{}, err
	}
	// 3. receive CA certificate
	return reply, nil
}

func InitNode(url string, port string, subject string, caport string) (*protocol.Identity, error) {
	if len(subject) > 32 {
		return nil, fmt.Errorf("subject length must be less than 32 bytes")
	}
	// Initialize node's public key and private key
	fmt.Printf("Connecting to CA server at %s:%s\n", url, caport)
	localPubKey, privKey, err := InitNodeKeys()
	if err != nil {
		fmt.Printf("InitNodeKeys failed: %v\n", err)
		return nil, err
	}

	log.Println("Node public key: ", localPubKey)

	// Request for CA, get certificate and put it in OwnCert
	cert, err := RequestCA(localPubKey, []byte(subject), url, caport)
	if err != nil {
		fmt.Printf("RequestCA failed: %v\n", err)
		return nil, err
	}

	// Local CA
	localCA := ca.NewLocalCA()
	localCA.Cert = cert

	localCA.PutPrivKey(privKey)

	// Set CA public key
	pubkey := config.GetCAPubKey()
	// Initialize identity
	var caPubKey [32]byte
	copy(caPubKey[:], pubkey)
	identity := &protocol.Identity{
		CAPubKey: caPubKey,
		OwnCert:  *localCA,
	}

	// Verifying correctness of signature
	if !identity.OwnCert.Cert.Verify(config.GetCAPubKey()) {
		return nil, fmt.Errorf("CA certificate signature verification failed")
	}

	return identity, nil
}
