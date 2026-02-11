# sanctum-sdk-go

Go SDK for [SanctumAI](https://sanctumai.dev) — credential management for AI agents.

## Features

- Unix socket and TCP connections
- JSON-RPC with 4-byte length-prefix framing
- Ed25519 challenge-response authentication
- Structured error types with actionable suggestions
- Context-based cancellation on all operations
- Use-not-retrieve pattern for secure credential operations

## Installation

```bash
go get github.com/jwgale/sanctum-sdk-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    sanctum "github.com/jwgale/sanctum-sdk-go"
)

func main() {
    ctx := context.Background()

    client, err := sanctum.NewClient("/var/run/sanctum.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    creds, err := client.List(ctx)
    if err != nil {
        log.Fatal(err)
    }
    for _, c := range creds {
        fmt.Println(c.Path)
    }
}
```

## API

| Function | Description |
|----------|-------------|
| `NewClient(socketPath)` | Connect via Unix socket |
| `NewTCPClient(addr)` | Connect via TCP |
| `Authenticate(ctx, agent, key)` | Ed25519 challenge-response auth |
| `Retrieve(ctx, path, ttl)` | Get credential with lease |
| `List(ctx)` | List available credentials |
| `ReleaseLease(ctx, leaseID)` | Release a credential lease |
| `Use(ctx, path, op, params)` | Use without retrieving |
| `Close()` | Close the connection |

## License

MIT
