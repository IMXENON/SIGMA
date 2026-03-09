package node

import (
	"crypto_protocols/sigma/connection"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type TraceEvent struct {
	Time    time.Time
	From    string
	To      string
	Epoch   uint16
	TxCount uint16
}

type SimpleTracker struct {
	mu     sync.Mutex
	events []TraceEvent
	limit  int
}

func NewSimpleTracker(limit int) *SimpleTracker {
	return &SimpleTracker{
		events: make([]TraceEvent, 0, limit),
		limit:  limit,
	}
}

// LogEvent 会记录 from->to 的消息，同时保证最多保留 limit 条
func (t *SimpleTracker) LogEvent(from, to string, epoch, tx uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.events) >= t.limit {
		// 移除最老的一条，保证 ring buffer 长度为 limit
		copy(t.events, t.events[1:])
		t.events = t.events[:t.limit-1]
	}

	t.events = append(t.events, TraceEvent{
		Time:    time.Now(),
		From:    from,
		To:      to,
		Epoch:   epoch,
		TxCount: tx,
	})
}

func (t *SimpleTracker) ExportHTML(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var seq strings.Builder
	seq.WriteString("sequenceDiagram\n")

	for _, e := range t.events {
		seq.WriteString(fmt.Sprintf(
			"%s->>%s: epoch=%d tx=%d\n",
			e.From,
			e.To,
			e.Epoch,
			e.TxCount,
		))
	}

	html := fmt.Sprintf(`
<html>
<head>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
</head>

<body>

<div class="mermaid">
%s
</div>

<script>
mermaid.initialize({startOnLoad:true});
</script>

</body>
</html>
`, seq.String())

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(html), 0644)
}

func TestAsymmetricMessagingVisualRandom(t *testing.T) {
	// 模拟连接
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	nodeA := setupTestIdentity("Alice")
	nodeB := setupTestIdentity("Bob")

	scA := connection.NewSecureConn(connA, "8080", "127.0.0.1", connection.RoleInitiator)
	scB := connection.NewSecureConn(connB, "8081", "127.0.0.1", connection.RoleResponder)

	// trace tracker (固定容量 ring buffer)
	tracker := NewSimpleTracker(1000)

	errChan := make(chan error, 2)

	// handshake Alice
	go func() {
		if err := scA.HandshakeAsInitiator(&nodeA.Identity); err != nil {
			errChan <- fmt.Errorf("Alice handshake failed: %v", err)
			return
		}
		scA.SetState(connection.ConnStateEstablished)
		scA.FinalizeHandshake(0)
		nodeA.RegisterConnection(scA)
		go nodeA.StartReceiver(scA)
		errChan <- nil
	}()

	// handshake Bob
	go func() {
		if err := scB.HandshakeAsResponder(&nodeB.Identity); err != nil {
			errChan <- fmt.Errorf("Bob handshake failed: %v", err)
			return
		}
		scB.SetState(connection.ConnStateEstablished)
		scB.FinalizeHandshake(0)
		nodeB.RegisterConnection(scB)
		go nodeB.StartReceiver(scB)
		errChan <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	}

	targetB := ProcessSubject("Bob")
	targetA := ProcessSubject("Alice")

	testMsg := []byte("hello")
	outerRounds := 1000000 // 外层循环轮数
	runtime.GOMAXPROCS(runtime.NumCPU())

	var wg sync.WaitGroup
	wg.Add(2)

	// Alice -> Bob
	go func() {
		defer wg.Done()
		for round := 0; round < outerRounds; round++ {
			// 随机 1~10 条消息
			msgCount := rand.Intn(10) + 1
			for i := 0; i < msgCount; i++ {
				sc, err := nodeA.getPeer(targetB)
				if err != nil {
					continue
				}
				tracker.LogEvent("Alice", "Bob", sc.GetEpoch(), sc.GetTxCount())
				nodeA.sendToPeer(targetB, testMsg)

				// 随机调度
				if rand.Intn(3) == 0 {
					runtime.Gosched()
				}
				if rand.Intn(5) == 0 {
					time.Sleep(time.Microsecond * time.Duration(rand.Intn(50)))
				}
			}
		}
	}()

	// Bob -> Alice
	go func() {
		defer wg.Done()
		for round := 0; round < outerRounds; round++ {
			msgCount := rand.Intn(10) + 1
			for i := 0; i < msgCount; i++ {
				sc, err := nodeB.getPeer(targetA)
				if err != nil {
					continue
				}
				tracker.LogEvent("Bob", "Alice", sc.GetEpoch(), sc.GetTxCount())
				nodeB.sendToPeer(targetA, testMsg)

				if rand.Intn(3) == 0 {
					runtime.Gosched()
				}
				if rand.Intn(5) == 0 {
					time.Sleep(time.Microsecond * time.Duration(rand.Intn(50)))
				}
			}
		}
	}()

	wg.Wait()

	time.Sleep(500 * time.Millisecond) // 等待 receiver 完成

	t.Logf("total %d events are stored in the tracker file", len(tracker.events))
	// 导出 HTML
	if err := tracker.ExportHTML("../trace/flow_trace.html"); err != nil {
		t.Fatalf("failed to export trace: %v", err)
	}

	t.Log("trace exported to ../trace/flow_trace.html")
}
