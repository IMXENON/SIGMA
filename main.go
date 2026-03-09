package main

import (
	"crypto_protocols/sigma/node"
	"flag"
	"fmt"
	"io"
	"log"
)

func main() {
	log.SetOutput(io.Discard)
	mode := flag.String("mode", "client", "运行模式: CA 或 client")
	port := flag.String("port", "8080", "运行端口")
	subject := flag.String("sub", "example.com", "客户端 Subject (仅 client 模式有效)")
	caport := flag.String("caport", "8081", "CA 服务器端口")
	flag.Parse()

	switch *mode {

	case "CA":
		node.StartCA(*port)

	case "client":
		node.StartClient(*port, *subject, *caport)

	default:
		fmt.Println("未知模式。请使用 -mode=CA 或 -mode=client")
	}
}
