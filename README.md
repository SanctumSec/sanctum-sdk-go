# sanctum-sdk-go

Native Go bindings for the [Sanctum](https://github.com/SanctumSec/sanctum) credential vault, powered by CGo wrapping `sanctum-ffi`.

## Installation

```bash
go get github.com/SanctumSec/sanctum-sdk-go
```

> **Note:** This package ships a prebuilt `libsanctum_ffi.dylib` for macOS (arm64). Linux support coming soon.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    sanctum "github.com/SanctumSec/sanctum-sdk-go"
)

func main() {
    // Initialize a new vault
    vault, err := sanctum.Init("/path/to/vault", []byte("passphrase"))
    if err != nil {
        log.Fatal(err)
    }
    defer vault.Close()

    // Store a credential
    vault.Store("api-key", []byte("sk-secret"), "my-agent", "")

    // Retrieve it
    secret, _ := vault.Retrieve("api-key", "my-agent")
    fmt.Printf("Secret: %s\n", secret)

    // Check audit log
    logJSON, _ := vault.AuditLog("")
    fmt.Println(logJSON)
}
```

## API

| Function | Description |
|----------|-------------|
| `Init(path, passphrase)` | Create and initialize a new vault |
| `Open(path, passphrase)` | Open an existing vault |
| `vault.Close()` | Free the vault handle |
| `vault.Store(name, secret, agentID, policyJSON)` | Store a credential |
| `vault.Retrieve(name, agentID)` | Retrieve a credential's secret |
| `vault.CheckPolicy(name, agentID)` | Check if an agent has access |
| `vault.AuditLog(agentIDFilter)` | Get audit log as JSON |

## Errors

Sentinel errors are provided for all FFI result codes:

- `ErrNotFound` — credential not found
- `ErrAccessDenied` — policy denies access
- `ErrNotInitialized` — vault not initialized
- `ErrCrypto` — cryptographic error
- See `errors.go` for the full list

## License

MIT
