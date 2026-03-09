package node

import (
	"crypto_protocols/sigma/ca_server"
	"fmt"
	"log"
)

func StartCA(port string) {
	addr := fmt.Sprintf("localhost:%s", port)
	fmt.Printf("启动 CA 服务器: %s\n", addr)

	go func() {
		if err := ca_server.StartCAServer(addr); err != nil {
			log.Fatalf("CA Server 启动失败: %v", err)
		}
	}()

	select {} // 阻塞主线程
}
