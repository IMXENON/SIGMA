package node

import (
	"bufio"
	"context"
	"crypto_protocols/sigma/connection"
	"crypto_protocols/sigma/protocol"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func StartClient(port, subject, caport string) {

	var wg sync.WaitGroup
	wg.Add(2)

	fmt.Printf("Responder: start client mode, subject: %s\n", subject)

	// Initialized identity information
	identity, err := InitNode("localhost", port, subject, caport)
	secureNode := NewSecureNode(identity, port)
	if err != nil {
		log.Fatalf("Responder: init node fail: %v", err)
	}

	fmt.Printf("Responder: node ready, cert sig preview: %x...\n",
		identity.OwnCert.Cert.Sig[:8])

	// Start listener and command loop
	go func() {
		defer wg.Done()
		secureNode.startListener(port)
	}()

	go func() {
		defer wg.Done()
		secureNode.startCommandLoop(identity, port)
	}()
	wg.Wait()
	fmt.Printf("Responder: client mode exit\n")
}

func (node *SecureNode) startListener(port string) {

	addr := "localhost:" + port

	lc := net.ListenConfig{
		KeepAlive: 30 * time.Second,
	}
	ln, err := lc.Listen(context.Background(), "tcp", addr)

	if err != nil {
		log.Fatalf("Responder: listen fail: %v", err)
	}

	log.Printf("Responder: start listen: %s\n", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go node.handleIncoming(conn, port)
	}
}

func (node *SecureNode) handleIncoming(conn net.Conn, port string) {

	secureConn := connection.NewSecureConn(conn, port, "localhost", connection.RoleResponder)

	err := secureConn.HandshakeAsResponder(&node.Identity)
	if err != nil {
		secureConn.Close()
		fmt.Println("Handshake fail:", err)
		return
	}

	// Destroy session after handshake and add peer into node's peer list, assuming the initialize epoch is 0
	err = secureConn.FinalizeHandshake(0)
	if err != nil {
		secureConn.Close()
		fmt.Println("FinalizeHandshake fail:", err)
		return
	}
	node.RegisterConnection(secureConn)
	fmt.Printf("\r[System] Successfully established secure link with %s\n> ", secureConn.GetRemoteSubject())
	go node.StartReceiver(secureConn)

}

func (node *SecureNode) startCommandLoop(identity *protocol.Identity, port string) {

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		cmd, _ := reader.ReadString('\n')
		cmd = strings.TrimSpace(cmd)

		switch {

		// Connect to a peer
		// Example: "connect Alice.com:8080"
		case strings.HasPrefix(cmd, "connect"):
			parts := strings.Split(cmd, " ")
			if len(parts) != 2 {
				fmt.Println("syntax error: should be connect host:port")
				continue
			}
			node.connectToPeer(parts[1], port)

			// Split input into target subject and the actual message
			// Example: "send Alice.com Hello there!" -> ["Alice", "Hello there!"]
		case strings.HasPrefix(cmd, "send"):
			rawParts := strings.Fields(cmd)
			if len(rawParts) < 3 {
				fmt.Println("syntax error: should be send <subject> <message>")
				continue
			}

			subject := rawParts[1]
			subjectStr := ProcessSubject(subject)
			firstTwoEnd := strings.Index(cmd, subject) + len(subject)
			message := strings.TrimSpace(cmd[firstTwoEnd:])

			node.sendToPeer(subjectStr, []byte(message))

		// Actively close connection
		case strings.HasPrefix(cmd, "close"):
			rawParts := strings.Fields(cmd)
			if len(rawParts) != 2 {
				fmt.Println("syntax error: should be close <subject>")
				continue
			}

			subject := rawParts[1]
			subjectStr := ProcessSubject(subject)

			conn, err := node.getPeer(subjectStr)
			if err != nil {
				fmt.Printf("Connection %s not found: %v\n", subjectStr, err)
				continue
			}

			node.UnregisterConnection(conn)

		// Mostly used for debugging, print message of node information
		case strings.HasPrefix(cmd, "print"):
			parts := strings.Split(cmd, " ")
			if len(parts) != 2 {
				fmt.Println("syntax error: should be print subject")
				continue
			}
			switch parts[1] {
			case "peers":
				fmt.Println("Peers:", node.peers)
			// Print physical address in memory of node
			// case "connection":
			// 	// Print connection information
			// 	fmt.Println("Connections:", node.Peers)

			default:
				fmt.Println("syntax error: unknown subject")
			}

		case strings.HasPrefix(cmd, "exit"):
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Unknown command:", cmd)
		}

	}
}

func (node *SecureNode) connectToPeer(addr string, port string) {

	fmt.Println("Initiator: connect to peer:", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("Initiator: connect fail:", err)
		return
	}

	// Create a session for the connection, inherit node's Identity

	secureConn := connection.NewSecureConn(conn, port, addr, connection.RoleInitiator)

	err = secureConn.HandshakeAsInitiator(&node.Identity)
	if err != nil {
		fmt.Println("Initiator: handshake fail:", err)
		// hooker, set instance secureConn to empty and close the connection
		secureConn.Close()

		secureConn.SetState(connection.ConnStateClosed)
		return
	}

	// Destroy session after handshake and add peer into node's peer list, assuming the initialize epoch is 0
	err = secureConn.FinalizeHandshake(0)
	if err != nil {
		fmt.Println("Initiator: finalize handshake fail:", err)
		// hooker, set instance secureConn to empty and close the connection
		secureConn.Close()

		secureConn.SetState(connection.ConnStateClosed)
		return
	}
	fmt.Println("Initiator: secure handshake success")

	secureConn.SetState(connection.ConnStateEstablished)
	node.RegisterConnection(secureConn)
	fmt.Printf("\r[System] Successfully established secure link with %s\n ", secureConn.GetRemoteSubject())
	go node.StartReceiver(secureConn)
}

func ProcessSubject(subject string) string {
	var subjectBuf [32]byte
	copy(subjectBuf[:], subject)
	return string(subjectBuf[:])
}
