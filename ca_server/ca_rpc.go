package ca_server

import (
	"crypto/ed25519"
	"crypto_protocols/sigma/ca"
	"net"
	"net/rpc"
)

type CAApi struct{}

type CAApplyRequest struct {
	ApplyerPubKey  ed25519.PublicKey
	ApplyerSubject []byte
}

func (t *CAApi) Apply(args *CAApplyRequest, reply *ca.SimpleCert) error {
	cert, err := HandleCAApplyRequest(args.ApplyerPubKey, args.ApplyerSubject)
	if err != nil {
		return err
	}
	*reply = cert
	return nil
}

func StartCAServer(addr string) error {
	api := new(CAApi)
	rpc.Register(api)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	rpc.Accept(listener)
	return nil
}
