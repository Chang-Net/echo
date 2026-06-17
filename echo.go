package echo

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Chang-Net/echo/protocols"
	"golang.org/x/crypto/ssh"
)

const (
	ProtocolVersion   uint8 = 1
	CloseFrameVersion uint8 = 255
)

type Config struct {
	Token       string
	IdleTimeout time.Duration
	Ctx         context.Context
}

type Client struct {
	cfg           Config
	protocols     []protocols.EchoProtocol
	activeChannel io.ReadWriteCloser
	activeProto   protocols.EchoProtocol
	mu            sync.Mutex
	idleTimer     *time.Timer
	privKeyPEM    []byte
	onMessage     func(data []byte)
}

func NewClient(cfg Config, onMessage func(data []byte)) *Client {
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	if cfg.Ctx == nil {
		cfg.Ctx = context.Background()
	}

	c := &Client{
		cfg:       cfg,
		protocols: make([]protocols.EchoProtocol, 0),
		onMessage: onMessage,
	}

	priv, _, err := GenerateSSHKeysFromToken(cfg.Token)
	if err == nil {
		c.privKeyPEM = priv
	}

	return c
}

func (c *Client) AddProtocol(p protocols.EchoProtocol) {
	c.protocols = append(c.protocols, p)
}

func (c *Client) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	frame, err := Encode(ProtocolVersion, data)
	if err != nil {
		return err
	}

	c.resetIdleTimer()

	if c.activeChannel != nil {
		_, err := c.activeChannel.Write(frame)
		if err == nil {
			return nil
		}
		c.activeChannel.Close()
		c.activeChannel = nil
	}

	for _, p := range c.protocols {
		rw, err := p.ClientOpen(c.cfg.Ctx, c.cfg.Token, c.privKeyPEM)
		if err == nil {
			c.activeChannel = rw
			c.activeProto = p

			go c.listenForServerMessages(rw)

			_, err = c.activeChannel.Write(frame)
			if err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("echo: all configured protocols failed to establish handshake")
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.activeChannel == nil {
		return nil
	}

	closeFrame, _ := Encode(CloseFrameVersion, nil)
	c.activeChannel.Write(closeFrame)

	c.activeChannel.Close()
	c.activeChannel = nil
	c.activeProto = nil

	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}

	return nil
}

func (c *Client) listenForServerMessages(rw io.ReadWriteCloser) {
	buf := make([]byte, 65535)
	for {
		n, err := rw.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			return
		}

		frame := buf[:n]
		version, data, err := Decode(frame)
		if err != nil {
			return
		}

		if version == CloseFrameVersion {
			c.mu.Lock()
			if c.activeChannel != nil {
				rw.Close()
				c.activeChannel = nil
				c.activeProto = nil
			}
			c.mu.Unlock()
			return
		}

		if version != ProtocolVersion {
			c.mu.Lock()
			if c.activeChannel != nil {
				rw.Close()
				c.activeChannel = nil
				c.activeProto = nil
			}
			c.mu.Unlock()
			return
		}

		if c.onMessage != nil && len(data) > 0 {
			go c.onMessage(data)
		}
	}
}

func (c *Client) resetIdleTimer() {
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	c.idleTimer = time.AfterFunc(c.cfg.IdleTimeout, func() {
		c.Close()
	})
}

type ServerConn struct {
	rw       io.ReadWriteCloser
	clientIP string
	listener *Listener
}

func (s *ServerConn) Send(data []byte) error {
	frame, err := Encode(ProtocolVersion, data)
	if err != nil {
		return err
	}

	_, err = s.rw.Write(frame)
	return err
}

func (s *ServerConn) Close() error {
	closeFrame, _ := Encode(CloseFrameVersion, nil)
	s.rw.Write(closeFrame)

	s.listener.mu.Lock()
	delete(s.listener.connections, s.clientIP)
	s.listener.mu.Unlock()

	return s.rw.Close()
}

func (s *ServerConn) ClientIP() string {
	return s.clientIP
}

type Listener struct {
	cfg         Config
	connections map[string]*ServerConn
	mu          sync.Mutex
	pubKeySSH   []byte
}

func NewListener(cfg Config) *Listener {
	l := &Listener{
		cfg:         cfg,
		connections: make(map[string]*ServerConn),
	}

	_, pub, err := GenerateSSHKeysFromToken(cfg.Token)
	if err == nil {
		l.pubKeySSH = pub
	}

	return l
}

func (l *Listener) ActivateProtocol(p protocols.EchoProtocol, listenAddr string, onConnect func(conn *ServerConn)) error {
	return p.ServerListen(listenAddr, l.cfg.Token, l.pubKeySSH, func(clientIP string, frame []byte, rw io.ReadWriteCloser) {
		version, _, err := Decode(frame)
		if err != nil {
			rw.Close()
			return
		}

		if version == CloseFrameVersion {
			l.mu.Lock()
			delete(l.connections, clientIP)
			l.mu.Unlock()
			rw.Close()
			return
		}

		if version != ProtocolVersion {
			rw.Close()
			return
		}

		l.mu.Lock()
		if _, exists := l.connections[clientIP]; !exists {
			sConn := &ServerConn{
				rw:       rw,
				clientIP: clientIP,
				listener: l,
			}
			l.connections[clientIP] = sConn
			l.mu.Unlock()

			go onConnect(sConn)
			go l.listenForClientMessages(sConn)
		} else {
			l.mu.Unlock()
		}
	})
}

func (l *Listener) listenForClientMessages(sConn *ServerConn) {
	buf := make([]byte, 65535)
	for {
		n, err := sConn.rw.Read(buf)
		if err != nil {
			l.mu.Lock()
			delete(l.connections, sConn.clientIP)
			l.mu.Unlock()
			return
		}

		frame := buf[:n]
		version, _, err := Decode(frame)
		if err != nil {
			l.mu.Lock()
			delete(l.connections, sConn.clientIP)
			l.mu.Unlock()
			sConn.rw.Close()
			return
		}

		if version == CloseFrameVersion {
			l.mu.Lock()
			delete(l.connections, sConn.clientIP)
			l.mu.Unlock()
			sConn.rw.Close()
			return
		}

		if version != ProtocolVersion {
			l.mu.Lock()
			delete(l.connections, sConn.clientIP)
			l.mu.Unlock()
			sConn.rw.Close()
			return
		}
	}
}

func GenerateSSHKeysFromToken(token string) (privateKeyPEM []byte, publicKeySSH []byte, err error) {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	seed := hasher.Sum(nil)

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	asn1Bytes, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM = pem.EncodeToMemory(asn1Bytes)

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeySSH = ssh.MarshalAuthorizedKey(sshPubKey)

	return privateKeyPEM, publicKeySSH, nil
}
