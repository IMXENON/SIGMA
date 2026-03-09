package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto_protocols/sigma/ca"
	"crypto_protocols/sigma/ca_server"
	"crypto_protocols/sigma/connection"
	"crypto_protocols/sigma/protocol"
	"fmt"
	mrand "math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// setupTestIdentity 使用本地 CA 模拟生成节点身份
func setupTestIdentity(subjectStr string) *SecureNode {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	cert, err := ca_server.HandleCAApplyRequest(pub, []byte(subjectStr))
	if err != nil {
		panic(err)
	}

	var caPubKey [32]byte
	caPubKeyBytes := []byte{
		0xd7, 0x04, 0x3b, 0x20, 0xf2, 0x37, 0x01, 0x3e,
		0x70, 0xd4, 0x30, 0x04, 0xf5, 0x54, 0xc5, 0x86,
		0x93, 0x01, 0x5f, 0xbd, 0xd7, 0x24, 0xb3, 0x56,
		0xa5, 0xee, 0x33, 0x56, 0x8e, 0xe4, 0xbb, 0xa7,
	}
	copy(caPubKey[:], caPubKeyBytes)

	localCA := ca.NewLocalCA()
	localCA.Cert = cert
	localCA.PutPrivKey(priv)

	id := &protocol.Identity{
		CAPubKey: caPubKey,
		OwnCert:  *localCA,
	}

	return NewSecureNode(id, "0")
}

func TestFullRefreshCycle(t *testing.T) {
	// 1. 使用 net.Pipe 构建模拟连接
	connA, connB := net.Pipe()

	// 2. 准备节点身份
	nodeA := setupTestIdentity("Alice")
	nodeB := setupTestIdentity("Bob")

	scA := connection.NewSecureConn(connA, "8080", "127.0.0.1", connection.RoleInitiator)
	scB := connection.NewSecureConn(connB, "8081", "127.0.0.1", connection.RoleResponder)

	errChan := make(chan error, 2)

	// 3. Initiator: Alice
	go func() {
		defer func() { errChan <- nil }()
		if err := scA.HandshakeAsInitiator(&nodeA.Identity); err != nil {
			errChan <- fmt.Errorf("Alice handshake failed: %v", err)
			return
		}
		scA.SetState(connection.ConnStateEstablished)
		scA.FinalizeHandshake(0)
		scA.PrintDebugRemoteSubject()
		nodeA.RegisterConnection(scA)
		go nodeA.StartReceiver(scA)
	}()

	// 4. Responder: Bob
	go func() {
		defer func() { errChan <- nil }()
		if err := scB.HandshakeAsResponder(&nodeB.Identity); err != nil {
			errChan <- fmt.Errorf("Bob handshake failed: %v", err)
			return
		}
		scB.SetState(connection.ConnStateEstablished)
		scB.FinalizeHandshake(0)
		scB.PrintDebugRemoteSubject()
		nodeB.RegisterConnection(scB)
		go nodeB.StartReceiver(scB)
	}()

	// 5. 等待握手完成
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Initial handshake failed: %v", err)
		}
	}

	// 7. 获取对方 subject
	targetB := ProcessSubject("Bob")
	targetA := ProcessSubject("Alice")

	// 8. 发送多条消息触发 refresh handshake
	fmt.Println("INFO: Checking refresh handshake after 5 rounds of 5 messages each, waiting for handshake")
	testMsg := []byte("messages")
	for round := 0; round < 5; round++ {
		for i := 0; i < 5; i++ {
			nodeA.sendToPeer(targetB, testMsg)
		}
		nodeB.sendToPeer(targetA, testMsg)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("INFO: Checking refresh handshake after 5 rounds of 10 messages each, not waiting for handshake")
	for round := 0; round < 5; round++ {
		for i := 0; i < 10; i++ {
			nodeA.sendToPeer(targetB, testMsg)
		}
		nodeB.sendToPeer(targetA, testMsg)
		nodeB.sendToPeer(targetA, testMsg)
	}

	fmt.Println("INFO: Fuzzing randomly much messages from random peer")
	for i := 0; i < 1000; i++ {
		r := time.Now().UnixNano() % 2
		if r == 0 {
			nodeA.sendToPeer(targetB, testMsg)
		} else {
			nodeB.sendToPeer(targetA, testMsg)
		}
	}
	time.Sleep(500 * time.Millisecond)

	// 9. 等待刷新完成
	time.Sleep(1 * time.Second)

	// 10. 验证刷新是否成功
	updatedScA, err := nodeA.getPeer(targetB)
	if err != nil {
		t.Fatalf("Failed to get updated connection: %v", err)
	}

	if updatedScA.GetEpoch() == 0 {
		t.Error("FAIL: Epoch remained at 0, refresh was not triggered or failed.")
	} else {
		t.Logf("SUCCESS: Connection refreshed. Current Epoch: %d", updatedScA.GetEpoch())
	}
}

func TestRandomTimeMessaging(t *testing.T) {
	connA, connB := net.Pipe()

	nodeA := setupTestIdentity("Alice")
	nodeB := setupTestIdentity("Bob")

	scA := connection.NewSecureConn(connA, "8080", "127.0.0.1", connection.RoleInitiator)
	scB := connection.NewSecureConn(connB, "8081", "127.0.0.1", connection.RoleResponder)

	errChan := make(chan error, 2)

	go func() {
		defer func() { errChan <- nil }()
		if err := scA.HandshakeAsInitiator(&nodeA.Identity); err != nil {
			errChan <- fmt.Errorf("Alice handshake failed: %v", err)
			return
		}
		scA.SetState(connection.ConnStateEstablished)
		scA.FinalizeHandshake(0)
		scA.PrintDebugRemoteSubject()
		nodeA.RegisterConnection(scA)
		go nodeA.StartReceiver(scA)
	}()

	go func() {
		defer func() { errChan <- nil }()
		if err := scB.HandshakeAsResponder(&nodeB.Identity); err != nil {
			errChan <- fmt.Errorf("Bob handshake failed: %v", err)
			return
		}
		scB.SetState(connection.ConnStateEstablished)
		scB.FinalizeHandshake(0)
		scB.PrintDebugRemoteSubject()
		nodeB.RegisterConnection(scB)
		go nodeB.StartReceiver(scB)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Initial handshake failed: %v", err)
		}
	}

	targetB := ProcessSubject("Bob")
	targetA := ProcessSubject("Alice")
	testMsg := []byte("messages")

	fmt.Println("INFO: Fuzzing randomly much messages from random peer")
	for i := 0; i < 100000; i++ {

		b := make([]byte, 1)
		rand.Read(b)
		r := b[0] % 2

		if r == 0 {
			nodeA.sendToPeer(targetB, testMsg)
		} else {
			nodeB.sendToPeer(targetA, testMsg)
		}

		if i%100 == 0 {
			epochA, _ := nodeA.getPeer(targetB)
			epochB, _ := nodeB.getPeer(targetA)
			fmt.Printf("Fuzz progress: i=%d, epochA=%d, epochB=%d\n", i, epochA.GetEpoch(), epochB.GetEpoch())
		}
	}

	updatedScA, err := nodeA.getPeer(targetB)
	if err != nil {
		t.Fatalf("Failed to get updated connection: %v", err)
	}

	if updatedScA.GetEpoch() == 0 {
		t.Error("FAIL: Epoch remained at 0, refresh was not triggered or failed.")
	} else {
		t.Logf("SUCCESS: Connection refreshed. Current Epoch: %d", updatedScA.GetEpoch())
	}
}

func TestAsymmetricMessagingStress(t *testing.T) {
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	nodeA := setupTestIdentity("Alice")
	nodeB := setupTestIdentity("Bob")

	scA := connection.NewSecureConn(connA, "8080", "127.0.0.1", connection.RoleInitiator)
	scB := connection.NewSecureConn(connB, "8081", "127.0.0.1", connection.RoleResponder)
	defer scA.Close()
	defer scB.Close()

	errChan := make(chan error, 2)

	// Alice handshake
	go func() {
		var err error
		if err = scA.HandshakeAsInitiator(&nodeA.Identity); err == nil {
			scA.SetState(connection.ConnStateEstablished)
			scA.FinalizeHandshake(0)
			nodeA.RegisterConnection(scA)
			go nodeA.StartReceiver(scA)
		}
		errChan <- err
	}()

	// Bob handshake
	go func() {
		var err error
		if err = scB.HandshakeAsResponder(&nodeB.Identity); err == nil {
			scB.SetState(connection.ConnStateEstablished)
			scB.FinalizeHandshake(0)
			nodeB.RegisterConnection(scB)
			go nodeB.StartReceiver(scB)
		}
		errChan <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Initial handshake failed: %v", err)
		}
	}

	targetB := ProcessSubject("Bob")
	targetA := ProcessSubject("Alice")
	testMsg := []byte("messages")

	runtime.GOMAXPROCS(runtime.NumCPU())
	var wg sync.WaitGroup
	wg.Add(2)

	outerRounds := 50000 // 保持适中循环

	// Alice -> Bob
	go func() {
		defer wg.Done()
		for round := 0; round < outerRounds; round++ {
			msgCount := mrand.Intn(5) + 1
			for i := 0; i < msgCount; i++ {

				err := nodeA.sendToPeer(targetB, testMsg)
				if err != nil {
					return
				}
				// 随机调度/微秒级 sleep
				if mrand.Intn(5) == 0 {
					time.Sleep(time.Microsecond * time.Duration(mrand.Intn(20)))
				}
			}
		}
	}()

	// Bob -> Alice
	go func() {
		defer wg.Done()
		for round := 0; round < outerRounds; round++ {
			msgCount := mrand.Intn(5) + 1
			for i := 0; i < msgCount; i++ {
				err := nodeB.sendToPeer(targetA, testMsg)
				if err != nil {
					return
				}

				if mrand.Intn(5) == 0 {
					time.Sleep(time.Microsecond * time.Duration(mrand.Intn(20)))
				}
			}
		}
	}()

	wg.Wait()

	// 等待 refresh handshake 完成
	time.Sleep(1 * time.Second)

	updatedScA, err := nodeA.getPeer(targetB)
	if err != nil {
		t.Fatalf("Failed to get updated connection: %v", err)
	}

	if updatedScA.GetEpoch() == 0 {
		t.Error("FAIL: Epoch remained at 0, refresh may not have completed")
	} else {
		t.Logf("SUCCESS: Connection refreshed. Current Epoch: %d", updatedScA.GetEpoch())
	}
}
