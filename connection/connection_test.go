package connection

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto_protocols/sigma/protocol"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

var testKey1 = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

func newTestConn() (*SecureConn, *SecureConn) {
	c1, c2 := net.Pipe()

	scA := NewSecureConn(c1, "127.0.0.1", "8081", RoleInitiator)
	scB := NewSecureConn(c2, "127.0.0.1", "8080", RoleResponder)

	scA.Session = protocol.NewSession(&protocol.Identity{})
	scB.Session = protocol.NewSession(&protocol.Identity{})

	sharedKey := testKey1

	deriveGCM := func(key []byte, label string) cipher.AEAD {
		subKey := make([]byte, 32)
		kdf := hkdf.New(sha256.New, key, nil, []byte(label))
		io.ReadFull(kdf, subKey)
		block, _ := aes.NewCipher(subKey)
		gcm, _ := cipher.NewGCM(block)
		return gcm
	}

	msgGCM := deriveGCM(sharedKey, "Session")
	headerGCM := deriveGCM(sharedKey, "Header")

	setup := func(sc *SecureConn) {
		sc.mu.Lock()
		sc.keys[sc.epoch] = &AEADkey{
			msgAEAD:    msgGCM,
			headerAEAD: headerGCM,
		}
		sc.State = ConnStateEstablished
		sc.mu.Unlock()
	}

	setup(scA)
	setup(scB)

	return scA, scB
}

// Table test:
func TestWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"normal", []byte("secure message")},
		{"binary", []byte{0x00, 0x01, 0xff, 0x10}},
		{"large", make([]byte, 4096)}, // 测试大数据包
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scA, scB := newTestConn()
			defer scA.RawConn.Close()
			defer scB.RawConn.Close()

			msgChan := make(chan *Msg, 1)
			errChan := make(chan error, 1)

			go func() {
				msg, err := scB.ReadEnc()
				if err != nil {
					errChan <- err
					return
				}
				msgChan <- msg
			}()

			err := scA.WriteEnc(MsgTypeData, c.payload)
			if err != nil {
				t.Fatalf("WriteEnc failed: %v", err)
			}

			select {
			case err := <-errChan:
				t.Fatalf("ReadEnc failed: %v", err)
			case receivedMsg := <-msgChan:
				if !bytes.Equal(c.payload, receivedMsg.GetOriginalPayload()) {
					t.Errorf("Payload mismatch!\nExp: %x\nGot: %x", c.payload, receivedMsg.GetOriginalPayload())
				}
				if receivedMsg.HeaderHidden.MsgType != MsgTypeData {
					t.Errorf("Type mismatch! Got: %v", receivedMsg.HeaderHidden.MsgType)
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Test timeout")
			}
		})
	}
}

// TODO: test epoch in different scenarios
func TestHeaderFields(t *testing.T) {
	scA, scB := newTestConn()
	defer scA.RawConn.Close()
	defer scB.RawConn.Close()

	payload := []byte("hello")

	go scA.WriteEnc(MsgTypeData, payload)

	msg, err := scB.ReadEnc()
	if err != nil {
		t.Fatal(err)
	}

	if msg.HeaderExploit.Epoch != 0 {
		t.Fatalf("wrong epoch: %d", msg.HeaderExploit.Epoch)
	}

	if msg.HeaderHidden.TxCount != 0 {
		t.Fatalf("wrong txCount: %d", msg.HeaderHidden.TxCount)
	}

	if msg.HeaderHidden.MsgType != MsgTypeData {
		t.Fatalf("wrong msg type")
	}
}

// TODO: payload tempering
func TestHeaderTamper(t *testing.T) {
	// 1. 初始化一对 Mock 连接
	scA, scB := newTestConn()
	defer scA.RawConn.Close()
	defer scB.RawConn.Close()

	payload := []byte("sensitive data")

	// 2. 模拟发送端加密过程
	msg, err := scA.PackMsg(MsgTypeData, payload)
	if err != nil {
		t.Fatalf("PackMsg failed: %v", err)
	}

	// 得到完整的加密帧 [HeaderPublic | Nonce | Ciphertext | Tag]
	frame, err := scA.EncryptAll(msg)
	if err != nil {
		t.Fatalf("EncryptAll failed: %v", err)
	}

	// 3. 实施篡改 (Tamper)
	// 假设 frame[0-5] 是 HeaderPublic (AAD)
	// 改变其中一个位，AEAD 的 Tag 校验就会失效
	frame[1] ^= 0xFF

	// 4. 将篡改后的数据注入管道
	go func() {
		_, _ = scA.RawConn.Write(frame)
	}()

	// 5. 接收端尝试读取并解密
	// ReadEnc 内部会调用 DecryptHeader 和 DecryptPayload
	_, err = scB.ReadEnc()

	// 6. 验证：必须报错才说明协议是安全的
	if err == nil {
		t.Fatal("Security Breach: Tampered header was NOT detected by AEAD!")
	}

	t.Logf("Success: Detected tampering as expected: %v", err)
}

func TestPayloadTamper(t *testing.T) {
	// 1. 初始化一对 Mock 连接
	scA, scB := newTestConn()
	defer scA.RawConn.Close()
	defer scB.RawConn.Close()

	payload := []byte("sensitive data")

	// 2. 模拟发送端加密过程
	msg, err := scA.PackMsg(MsgTypeData, payload)
	if err != nil {
		t.Fatalf("PackMsg failed: %v", err)
	}

	// 得到完整的加密帧 [HeaderPublic | Nonce | Ciphertext | Tag]
	frame, err := scA.EncryptAll(msg)
	if err != nil {
		t.Fatalf("EncryptAll failed: %v", err)
	}

	// 3. 实施篡改 (Tamper)
	// 假设 frame[0-5] 是 HeaderPublic (AAD)
	// 改变其中一个位，AEAD 的 Tag 校验就会失效
	frame[len(frame)-1] ^= 0xFF

	// 4. 将篡改后的数据注入管道
	go func() {
		_, _ = scA.RawConn.Write(frame)
	}()

	// 5. 接收端尝试读取并解密
	// ReadEnc 内部会调用 DecryptHeader 和 DecryptPayload
	_, err = scB.ReadEnc()

	// 6. 验证：必须报错才说明协议是安全的
	if err == nil {
		t.Fatal("Security Breach: Tampered header was NOT detected by AEAD!")
	}

	t.Logf("Success: Detected tampering as expected: %v", err)
}

func TestTxCountIncrease(t *testing.T) {
	scA, scB := newTestConn()
	defer scA.RawConn.Close()
	defer scB.RawConn.Close()

	// 1. 创建一个 Channel 来接收读取到的消息
	results := make(chan *Msg, 3)

	// 2. 启动协程异步读取
	go func() {
		for i := 0; i < 3; i++ {
			msg, err := scB.ReadEnc()
			if err != nil {
				return
			}
			results <- msg
		}
	}()

	// 3. 现在同步写入就不会阻塞了，因为后台有人在读
	scA.WriteEnc(MsgTypeData, []byte("a"))
	scA.WriteEnc(MsgTypeData, []byte("b"))
	scA.WriteEnc(MsgTypeData, []byte("c"))

	// 4. 从 Channel 中取出结果进行断言
	msg1 := <-results
	msg2 := <-results
	msg3 := <-results

	if msg1.HeaderHidden.TxCount != 0 || msg2.HeaderHidden.TxCount != 1 || msg3.HeaderHidden.TxCount != 2 {
		t.Fatalf("txcount 顺序错误: msg1=%d, msg2=%d, msg3=%d",
			msg1.HeaderHidden.TxCount, msg2.HeaderHidden.TxCount, msg3.HeaderHidden.TxCount)
	}
}

func TestTruncatedFrame(t *testing.T) {

	scA, scB := newTestConn()
	defer scA.RawConn.Close()
	defer scB.RawConn.Close()

	payload := []byte("hello")

	msg, err := scA.PackMsg(MsgTypeData, payload)
	if err != nil {
		t.Fatalf("PackMsg failed: %v", err)
	}

	frame, err := scA.EncryptAll(msg)
	if err != nil {
		t.Fatalf("EncryptAll failed: %v", err)
	}

	// 3. 实施截断 (Truncate)
	// 只保留前半部分，这会导致 AEAD 标签（Tag）丢失或 AAD 长度不匹配
	truncatedFrame := frame[:len(frame)/2]

	// 4. 直接调用解密逻辑进行测试
	// 注意：这里我们不走 ReadEnc，因为 ReadEnc 会在 io.ReadFull 处死等
	// 我们模拟 ReadEnc 内部的解密步骤

	// 尝试解密 Header
	// 假设你的 ExploitHeaderSize + AEADOverhead + HiddenHeaderSize 超过了 truncatedFrame 长度
	if len(truncatedFrame) < ExploitHeaderSize+AEADOverhead+HiddenHeaderSize {
		t.Log("Frame too short to even contain headers, test passed")
		return
	}

	ex, hi, err := scB.DecryptHeader(truncatedFrame[:ExploitHeaderSize+AEADOverhead+HiddenHeaderSize])
	if err != nil {
		// 如果在解密 Header 阶段就报错，说明测试成功
		t.Logf("Detected truncated header: %v", err)
		return
	}

	// 如果 Header 侥幸过了，尝试解密 Payload
	// 此时 payloadBuffer 长度肯定不对
	remaining := truncatedFrame[ExploitHeaderSize+AEADOverhead+HiddenHeaderSize:]
	_, err = scB.DecryptPayload(ex, hi, remaining)

	// 5. 验证：必须报错
	if err == nil {
		t.Fatal("Security Error: Truncated frame was accepted without error")
	}

	t.Logf("Success: Truncated frame rejected as expected: %v", err)
}

func TestRealNetworkTruncation(t *testing.T) {
	scA, scB := newTestConn()
	defer scA.RawConn.Close()
	defer scB.RawConn.Close()

	payload := []byte("highly confidential data")

	go func() {
		msg, _ := scA.PackMsg(MsgTypeData, payload)
		frame, _ := scA.EncryptAll(msg)
		scA.RawConn.Write(frame[:ExploitHeaderSize])

		scA.RawConn.Close()
	}()

	_, err := scB.ReadEnc()

	if err == nil {
		t.Fatal("错误：连接已断开且数据不全，ReadEnc 不该返回 nil 错误")
	}

	t.Logf("成功捕获网络截断错误: %v", err)
}

// 2. 只有 Header 部分（公开+加密），Payload 全没了
func TestReadEncWithNetworkTruncation(t *testing.T) {
	scA, scB := newTestConn()

	// 模拟对端发了一半就“拔网线”
	go func() {
		// 我们不调用 WriteEnc，因为 WriteEnc 会发全量数据
		// 我们手动发一部分 frame 模拟网络只传了一半的情况
		msg, _ := scA.PackMsg(MsgTypeData, []byte("secret"))
		frame, _ := scA.EncryptAll(msg)

		// 故意只发 ExploitHeaderSize + 1 个字节，让对方的 ReadFull 凑不满
		scA.RawConn.Write(frame[:ExploitHeaderSize+1])

		// 关键动作：关闭连接。这会导致 scB 的 ReadFull 立即返回错误
		scA.RawConn.Close()
	}()

	// 因为 scB 内部调用了 io.ReadFull(sc.RawConn, headerBuffer)
	// 此时它读不到足够的字节，就会报错
	_, err := scB.ReadEnc()

	if err == nil {
		t.Fatal("错误：网络断开了且数据没读够，ReadEnc 居然没报错")
	}

	// 在你的 ReadEnc 里，这个错误应该是 io.ErrUnexpectedEOF
	t.Logf("成功捕获到 ReadFull 的报错: %v", err)
}
