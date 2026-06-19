package echo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Chang-Net/echo/protocols"
	"golang.org/x/crypto/ssh"
)

const (
	ProtocolVersion   uint8 = 1
	CloseFrameVersion uint8 = 255

	MaxConcurrentWrites = 50
	BandwidthDelay      = 2 * time.Millisecond

	MaxServerWorkersPerConn = 100
)

type Config struct {
	Token       string
	IdleTimeout time.Duration
	Ctx         context.Context
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

type Client struct {
	cfg           Config
	protocols     []protocols.EchoProtocol
	activeChannel io.ReadWriteCloser
	mu            sync.RWMutex
	writeMu       sync.Mutex
	semaphore     chan struct{}
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
		semaphore: make(chan struct{}, MaxConcurrentWrites),
	}

	priv, _, err := GenerateSSHKeysFromToken(cfg.Token)
	if err == nil {
		c.privKeyPEM = priv
	}

	return c
}

func (c *Client) AddProtocol(p protocols.EchoProtocol) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.protocols = append(c.protocols, p)
}

func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.activeChannel != nil {
		return nil
	}

	for _, p := range c.protocols {
		rw, err := p.ClientOpen(c.cfg.Ctx, c.cfg.Token, c.privKeyPEM)
		if err == nil {
			c.activeChannel = rw
			go c.listenForServerMessages(rw)
			return nil
		}
	}
	return errors.New("echo: handshake failed, could not connect to any protocol")
}

func (c *Client) Send(data []byte) error {
	c.semaphore <- struct{}{}
	defer func() { <-c.semaphore }()

	c.mu.RLock()
	ch := c.activeChannel
	c.mu.RUnlock()

	if ch == nil {
		return errors.New("echo: client not connected. call Connect() first")
	}

	frame, err := Encode(ProtocolVersion, data)
	if err != nil {
		return err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	time.Sleep(BandwidthDelay)
	_, err = ch.Write(frame)

	return err
}

func (c *Client) Close() error {
	c.mu.Lock()
	ch := c.activeChannel
	c.activeChannel = nil
	c.mu.Unlock()

	if ch != nil {
		closeFrame, _ := Encode(CloseFrameVersion, nil)
		c.writeMu.Lock()
		_, _ = ch.Write(closeFrame)
		c.writeMu.Unlock()
		return ch.Close()
	}
	return nil
}

func (c *Client) listenForServerMessages(rw io.ReadWriteCloser) {
	defer rw.Close()
	for {
		version, data, err := ReadFrame(rw)
		if err != nil {
			return
		}

		if version == CloseFrameVersion || version != ProtocolVersion {
			return
		}

		if c.onMessage != nil && len(data) > 0 {
			go c.onMessage(data)
		}
	}
}

type ServerConn struct {
	rw         io.ReadWriteCloser
	clientIP   string
	listener   *Listener
	writeMu    sync.Mutex
	workerPool chan struct{}
}

func (s *ServerConn) Send(data []byte) error {
	frame, err := Encode(ProtocolVersion, data)
	if err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.rw.Write(frame)
	return err
}

func (s *ServerConn) Close() error {
	closeFrame, _ := Encode(CloseFrameVersion, nil)
	s.writeMu.Lock()
	_, _ = s.rw.Write(closeFrame)
	err := s.rw.Close()
	s.writeMu.Unlock()

	s.listener.removeConnection(s.clientIP)
	return err
}

type Listener struct {
	connections map[string]*ServerConn
	mu          sync.RWMutex
	pubKeySSH   []byte
	cfg         Config
}

func NewListener(cfg Config) *Listener {
	return &Listener{
		cfg:         cfg,
		connections: make(map[string]*ServerConn),
	}
}

func (l *Listener) removeConnection(clientIP string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.connections, clientIP)
}

func (l *Listener) ActivateProtocol(p protocols.EchoProtocol, listenAddr string, onMessage func(data []byte, conn *ServerConn)) error {
	if len(l.pubKeySSH) == 0 {
		_, pub, err := GenerateSSHKeysFromToken(l.cfg.Token)
		if err == nil {
			l.pubKeySSH = pub
		} else {
			return fmt.Errorf("echo: failed to generate server keys: %v", err)
		}
	}

	return p.ServerListen(listenAddr, l.cfg.Token, l.pubKeySSH, func(clientIP string, firstFrame []byte, rw io.ReadWriteCloser) {
		if len(firstFrame) < 3 {
			rw.Close()
			return
		}

		version, data, err := Decode(firstFrame)
		if err != nil || version == CloseFrameVersion || version != ProtocolVersion {
			rw.Close()
			return
		}

		l.mu.Lock()
		sConn, exists := l.connections[clientIP]
		if !exists {
			sConn = &ServerConn{
				rw:         rw,
				clientIP:   clientIP,
				listener:   l,
				workerPool: make(chan struct{}, MaxServerWorkersPerConn),
			}
			l.connections[clientIP] = sConn
			l.mu.Unlock()

			var reader io.Reader = rw
			expectedLen := 3 + int(binary.BigEndian.Uint16(firstFrame[1:3]))

			if len(firstFrame) > expectedLen {
				extraBytes := firstFrame[expectedLen:]
				reader = io.MultiReader(bytes.NewReader(extraBytes), rw)
			}

			go l.listenForClientMessagesWithReader(sConn, reader, onMessage)

			if len(data) > 0 {
				sConn.executeSafeMessage(data, onMessage)
			}
		} else {
			l.mu.Unlock()
			if len(data) > 0 {
				sConn.executeSafeMessage(data, onMessage)
			}
		}
	})
}

func (s *ServerConn) executeSafeMessage(data []byte, onMessage func([]byte, *ServerConn)) {
	if onMessage == nil {
		return
	}

	s.workerPool <- struct{}{}
	go func() {
		defer func() {
			<-s.workerPool
			if r := recover(); r != nil {
				fmt.Printf("[SERVER PANIC RECOVERED] IP: %s, Error: %v\n", s.clientIP, r)
			}
		}()
		onMessage(data, s)
	}()
}

func (l *Listener) listenForClientMessagesWithReader(sConn *ServerConn, r io.Reader, onMessage func(data []byte, conn *ServerConn)) {
	defer func() {
		sConn.rw.Close()
		l.removeConnection(sConn.clientIP)
	}()

	for {
		version, data, err := ReadFrame(r)
		if err != nil {
			return
		}

		if version == CloseFrameVersion || version != ProtocolVersion {
			return
		}

		if len(data) > 0 {
			sConn.executeSafeMessage(data, onMessage)
		}
	}
}
