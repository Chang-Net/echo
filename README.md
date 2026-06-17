

```markdown
# Echo Protocol

A stateless, ultra-lightweight, and minimal protocol designed to sit on top of other protocols for low-data, full-duplex packet communication.

---

### Server Configuration & Lifecycle

```go
// 1. Instance and Configuration
cfg := echo.Config{
    Token:       "your_secure_text_token",
    IdleTimeout: 5 * time.Second,
}
srv := echo.NewListener(cfg)
sshProto := protocols.NewSSHProtocol("0.0.0.0:8686")

// 2. Activate Protocol & Handle Full-Duplex I/O
srv.ActivateProtocol(sshProto, "0.0.0.0:8686", func(conn *echo.ServerConn) {
    log.Printf("Client connected from: %s", conn.ClientIP())

    // Asynchronously send data from Server to Client
    go func() {
        err := conn.Send([]byte("Hello from secure server"))
        if err != nil {
            log.Printf("Server send failed: %v", err)
        }
    }()
})

```

### Client Configuration & Lifecycle

```go
// 1. Configuration
cfg := echo.Config{
    Token:       "your_secure_text_token", // Must match the server's token
    IdleTimeout: 5 * time.Second,
}

// 2. Instance with explicit OnMessage handler callback for inbound server data
client := echo.NewClient(cfg, func(data []byte) {
    fmt.Printf("📥 Client Received: %s\n", string(data))
})
client.AddProtocol(protocols.NewSSHProtocol("server_ip:8686"))

// 3. Send data from Client to Server
err := client.Send([]byte("Hello from secure client"))
if err != nil {
    log.Fatalf("Client send failed: %v", err)
}

// 4. Graceful Close
defer client.Close()

```