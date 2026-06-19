# Echo Protocol

A stateless, ultra-lightweight, and minimal protocol designed to sit on top of other protocols for low-data, full-duplex packet communication. Optimized for stability and high concurrency.

---

### Server Configuration

```go
// 1. Initialize
cfg := echo.Config{
    Token:       "your_secure_text_token",
    IdleTimeout: 10 * time.Second,
}
srv := echo.NewListener(cfg)
sshProto := protocols.NewSSHProtocol("0.0.0.0:8686")

// 2. Activate Protocol
srv.ActivateProtocol(sshProto, "0.0.0.0:8686", func(data []byte, conn *echo.ServerConn) {
    // Handle inbound data safely
    fmt.Printf("Received from %s: %s\n", conn.ClientIP(), string(data))

    // Respond back
    conn.Send([]byte("Hello from server!"))
})

```

### Client Configuration & Lifecycle

```go
// 1. Initialize
cfg := echo.Config{
    Token:       "your_secure_text_token",
    IdleTimeout: 10 * time.Second,
}

// 2. Setup Client with incoming message handler
client := echo.NewClient(cfg, func(data []byte) {
    fmt.Printf("📥 Client Received: %s\n", string(data))
})
client.AddProtocol(protocols.NewSSHProtocol("server_ip:8686"))

// 3. Connect (Required: Establish handshake before sending)
if err := client.Connect(); err != nil {
    log.Fatalf("Handshake failed: %v", err)
}

// 4. Send Data
err := client.Send([]byte("Hello from secure client"))
if err != nil {
    log.Printf("Send failed: %v", err)
}

// 5. Graceful Close
defer client.Close()

```

---

### Key Features

* **Thread-Safe:** Designed for highly concurrent environments.
* **Flow Control:** Built-in rate limiting and bandwidth management to prevent socket congestion.
* **Resilient:** Panic-safe server handlers and automatic connection cleanup.
* **Eager Handshake:** Explicit connection management to ensure tunnel stability.

---
