package protocols

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHProtocol struct {
	Addr string
}

func NewSSHProtocol(addr string) *SSHProtocol {
	return &SSHProtocol{Addr: addr}
}

func (s *SSHProtocol) Name() string {
	return "SSH:" + s.Addr
}

func (s *SSHProtocol) ClientOpen(ctx context.Context, token string, privateKeyPEM []byte) (io.ReadWriteCloser, error) {
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, errors.New("ssh proto: failed to parse private key from RAM: " + err.Error())
	}

	config := &ssh.ClientConfig{
		User: "echo-user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         4 * time.Second,
	}

	conn, err := net.DialTimeout("tcp", s.Addr, 4*time.Second)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, s.Addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	channel, requests, err := client.OpenChannel("echo-proto", nil)
	if err != nil {
		client.Close()
		sshConn.Close()
		conn.Close()
		return nil, err
	}
	go ssh.DiscardRequests(requests)

	return &sshClientWrapper{channel: channel, client: client, sshConn: sshConn, conn: conn}, nil
}

type sshClientWrapper struct {
	channel ssh.Channel
	client  *ssh.Client
	sshConn ssh.Conn
	conn    net.Conn
}

func (w *sshClientWrapper) Write(p []byte) (n int, err error) { return w.channel.Write(p) }
func (w *sshClientWrapper) Read(p []byte) (n int, err error)  { return w.channel.Read(p) }
func (w *sshClientWrapper) Close() error {
	w.channel.Close()
	w.client.Close()
	w.sshConn.Close()
	return w.conn.Close()
}

func (s *SSHProtocol) ServerListen(addr string, token string, expectedClientPublicKeySSH []byte, onFrame func(string, []byte, io.ReadWriteCloser)) error {

	expectedPubKey, _, _, _, err := ssh.ParseAuthorizedKey(expectedClientPublicKeySSH)
	if err != nil {
		return errors.New("ssh proto: failed to parse expected public key: " + err.Error())
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if string(pubKey.Marshal()) == string(expectedPubKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("ssh proto: unauthorized public key")
		},
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	signer, _ := ssh.ParsePrivateKey(privateKeyPEM)
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go s.handleConnection(conn, config, onFrame)
		}
	}()
	return nil
}

func (s *SSHProtocol) handleConnection(conn net.Conn, config *ssh.ServerConfig, onFrame func(string, []byte, io.ReadWriteCloser)) {
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for newChannel := range chans {
		if newChannel.ChannelType() != "echo-proto" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(requests)

		go func(ch ssh.Channel) {
			defer conn.Close()
			defer ch.Close()

			buf := make([]byte, 65535)
			for {
				n, err := ch.Read(buf)
				if err != nil {
					return
				}

				onFrame(clientIP, buf[:n], ch)
			}
		}(channel)
	}
}
