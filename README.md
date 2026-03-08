# sanctum-sdk-go

Go SDK for [SanctumAI](https://github.com/SanctumSec/sanctum) — a local-first credential vault for AI agents.

Agents authenticate, request credentials through the vault, and ideally **never see raw secrets at all**. The vault acts as a proxy: your agent says *what* it wants to do, and Sanctum does it on the agent's behalf.

## Install

```bash
go get github.com/SanctumSec/sanctum-sdk-go
```

> **Platform support:** ships with a prebuilt `libsanctum_ffi.dylib` for macOS (arm64). Linux `.so` is built from source in CI.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    sanctum "github.com/SanctumSec/sanctum-sdk-go"
)

func main() {
    vault, err := sanctum.Open("/path/to/vault", []byte("passphrase"))
    if err != nil {
        log.Fatal(err)
    }
    defer vault.Close()

    // Use a credential without ever seeing it
    result, err := vault.UseCredential("openai/api-key", "my-agent", "http_request", map[string]interface{}{
        "method": "POST",
        "url":    "https://api.openai.com/v1/chat/completions",
        "headers": map[string]string{
            "Content-Type": "application/json",
        },
        "body":        `{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`,
        "header_type": "bearer",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Status:", result["status"])
    fmt.Println("Body:", result["body"])
}
```

The agent never touches the API key. Sanctum injects it into the request, makes the call, and returns the response.

## Use Don't Retrieve

`UseCredential` is the flagship method. Instead of retrieving a secret and using it yourself, you tell the vault *what to do* and it handles the credential injection. Your agent code never holds raw secrets in memory.

### Proxy an HTTP Request

The most common pattern — make an API call through the vault:

```go
result, err := vault.UseCredential("openai/api-key", "my-agent", "http_request", map[string]interface{}{
    "method": "POST",
    "url":    "https://api.openai.com/v1/chat/completions",
    "headers": map[string]string{
        "Content-Type": "application/json",
    },
    "body":        `{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`,
    "header_type": "bearer",
})
// result["status"]  → 200
// result["headers"] → response headers
// result["body"]    → response body
```

Supported `header_type` values: `bearer`, `api_key`, `basic`, `custom`.

### Get an HTTP Header

When you need to attach the credential to your own HTTP client:

```go
result, err := vault.UseCredential("github/token", "my-agent", "http_header", map[string]interface{}{
    "header_type": "bearer",
})
// result["header_name"]  → "Authorization"
// result["header_value"] → "Bearer ghp_..."
```

### Sign Data (HMAC)

Sign a payload without exposing the signing key:

```go
result, err := vault.UseCredential("webhook/secret", "my-agent", "sign", map[string]interface{}{
    "algorithm": "hmac-sha256",
    "data":      "payload-to-sign",
})
// result["signature"] → base64-encoded HMAC signature
```

### Encrypt / Decrypt

```go
encrypted, err := vault.UseCredential("data/key", "my-agent", "encrypt", map[string]interface{}{
    "data": "sensitive-payload",
})

decrypted, err := vault.UseCredential("data/key", "my-agent", "decrypt", map[string]interface{}{
    "data": encrypted["ciphertext"],
})
```

## API Reference

### Vault Lifecycle

| Function | Description |
|---|---|
| `sanctum.Init(path, passphrase)` | Create and initialize a new vault |
| `sanctum.Open(path, passphrase)` | Open an existing vault |
| `vault.Close()` | Free the vault handle (safe to call multiple times) |

### Credential Operations

| Method | Description |
|---|---|
| `vault.UseCredential(name, agentID, operation, params)` | Use a credential without seeing it (**recommended**) |
| `vault.Store(name, secret, agentID, policyJSON)` | Store a credential |
| `vault.Retrieve(name, agentID)` | Retrieve a credential's raw secret bytes |
| `vault.Delete(name, agentID)` | Remove a credential |
| `vault.ListCredentials(agentID)` | List credential paths (JSON array) |

### Access Control & Audit

| Method | Description |
|---|---|
| `vault.CheckPolicy(name, agentID)` | Check if an agent is allowed to access a credential |
| `vault.AuditLog(agentIDFilter)` | Get the audit log as JSON (filter by agent or pass `""` for all) |

### UseCredential Operations

| Operation | Params | Returns |
|---|---|---|
| `http_request` | `method`, `url`, `headers`, `body`, `header_type` | `status`, `headers`, `body` |
| `http_header` | `header_type` | `header_name`, `header_value` |
| `sign` | `algorithm`, `data` | `signature` |
| `encrypt` | `data` | `ciphertext` |
| `decrypt` | `data` | `plaintext` |

## Error Handling

All methods return Go errors. Sentinel errors let you handle specific failure modes:

```go
secret, err := vault.Retrieve("api-key", "my-agent")
if errors.Is(err, sanctum.ErrNotFound) {
    // credential doesn't exist
} else if errors.Is(err, sanctum.ErrAccessDenied) {
    // policy denies this agent access
}
```

| Sentinel | Meaning |
|---|---|
| `ErrNotFound` | Credential does not exist |
| `ErrAccessDenied` | Policy denies access |
| `ErrNotInitialized` | Vault not initialized at path |
| `ErrCrypto` | Cryptographic error |
| `ErrJSON` | JSON serialization error |

See [`errors.go`](errors.go) for the full list.

## Contributing

```bash
# Run tests (requires libsanctum_ffi in lib/)
go test -v ./...

# Lint
go vet ./...
```

## License

MIT
