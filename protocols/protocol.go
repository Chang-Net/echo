package protocols

import (
	"context"
	"io"
)

type EchoProtocol interface {
	Name() string
	ClientOpen(ctx context.Context, token string, privateKeyPEM []byte) (io.ReadWriteCloser, error)
	ServerListen(addr string, token string, publicKeySSH []byte, onFrame func(string, []byte, io.ReadWriteCloser)) error
}
