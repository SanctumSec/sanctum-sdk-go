# SanctumAI Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/jwgale/sanctum-sdk-go.svg)](https://pkg.go.dev/github.com/jwgale/sanctum-sdk-go)
[![Go](https://img.shields.io/badge/go-1.21%2B-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/jwgale/sanctum-sdk-go/actions/workflows/ci.yml/badge.svg)](https://github.com/jwgale/sanctum-sdk-go/actions/workflows/ci.yml)

> Part of the [SanctumAI](https://github.com/jwgale/sanctum) ecosystem — secure credential management for AI agents.

Go SDK for interacting with a SanctumAI vault. Supports Unix sockets and TCP, Ed25519 authentication, `context.Context` on all operations, structured error types, and the **use-not-retrieve** pattern.

## Installation

```bash
go get github.com/jwgale/sanctum-sdk-go
```

Requires **Go 1.21+**.

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

	// Connect via Unix socket
	client, err := sanctum.NewClient("/var/run/sanctum.sock")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// List available credentials
	creds, err := client.List(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range creds {
		fmt.Printf("  %s (tags: %v)\n", c.Path, c.Tags)
	}

	// Retrieve a credential (lease auto-tracked)
	cred, err := client.Retrieve(ctx, "openai/api_key", 300)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key starts with: %s...\n", cred.Value[:8])

	// Use-not-retrieve — credential never leaves the vault
	result, err := client.Use(ctx, "openai/api_key", "http_header", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Header: %s\n", result.Data["header"])
}
```

## Connecting

```go
// Unix socket
client, err := sanctum.NewClient("/var/run/sanctum.sock")

// TCP connection
client, err := sanctum.NewTCPClient("127.0.0.1:8200")

// With timeout context
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
cred, err := client.Retrieve(ctx, "database/primary", 300)
```

## Use-Not-Retrieve

The **use-not-retrieve** pattern lets agents perform operations that require a credential without ever exposing the secret to the agent process. The vault executes the operation server-side and returns only the result.

```go
ctx := context.Background()

// Sign a request — private key never leaves the vault
signed, err := client.Use(ctx, "signing/key", "sign_payload", map[string]string{
	"payload": "data-to-sign",
})

// Inject as HTTP header — agent never sees the raw token
header, err := client.Use(ctx, "openai/api_key", "http_header", nil)

// Encrypt data — encryption key stays in the vault
encrypted, err := client.Use(ctx, "encryption/key", "encrypt", map[string]string{
	"plaintext": "sensitive data",
})
```

This is the recommended pattern for production agents. Secrets never exist in agent memory.

## Error Handling

Errors can be type-asserted to `*sanctum.VaultError` for structured context:

```go
cred, err := client.Retrieve(ctx, "openai/api_key", 300)
if err != nil {
	var ve *sanctum.VaultError
	if errors.As(err, &ve) {
		switch ve.Code {
		case sanctum.ErrAccessDenied:
			fmt.Printf("No access: %s\n", ve.Detail)
			fmt.Printf("Suggestion: %s\n", ve.Suggestion)
		case sanctum.ErrCredentialNotFound:
			fmt.Printf("Not found: %s\n", ve.Detail)
		case sanctum.ErrAuthFailed:
			fmt.Println("Authentication failed — check your Ed25519 key")
		case sanctum.ErrVaultLocked:
			fmt.Println("Vault is sealed — an operator needs to unseal it")
		default:
			fmt.Printf("[%s] %s\n", ve.Code, ve.Detail)
			if ve.DocsURL != "" {
				fmt.Printf("Docs: %s\n", ve.DocsURL)
			}
		}
	} else {
		log.Fatal(err) // network error, etc.
	}
}
```

### Error Codes

| Constant | Code | Description |
|---|---|---|
| `ErrAuthFailed` | `AUTH_FAILED` | Authentication failed |
| `ErrAccessDenied` | `ACCESS_DENIED` | Insufficient permissions |
| `ErrCredentialNotFound` | `CREDENTIAL_NOT_FOUND` | Path doesn't exist |
| `ErrVaultLocked` | `VAULT_LOCKED` | Vault is sealed |
| `ErrLeaseExpired` | `LEASE_EXPIRED` | Lease timed out |
| `ErrRateLimited` | `RATE_LIMITED` | Too many requests |
| `ErrSessionExpired` | `SESSION_EXPIRED` | Re-authenticate needed |

`VaultError` carries `Code`, `Detail`, `Suggestion`, `DocsURL`, and `Context` fields.

## API Reference

| Function | Description |
|---|---|
| `NewClient(socketPath)` | Connect via Unix socket |
| `NewTCPClient(addr)` | Connect via TCP |
| `Authenticate(ctx, agent, key)` | Ed25519 challenge-response auth |
| `Retrieve(ctx, path, ttl)` | Get credential with lease |
| `List(ctx)` | List available credentials |
| `ReleaseLease(ctx, leaseID)` | Release a credential lease |
| `Use(ctx, path, op, params)` | Use without retrieving |
| `Close()` | Close the connection |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`go test ./...`)
5. Run `go vet` and `golangci-lint run`
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT — see [LICENSE](LICENSE).

## Links

- 🏠 **Main project:** [github.com/jwgale/sanctum](https://github.com/jwgale/sanctum)
- 🌐 **Website:** [sanctumai.dev](https://sanctumai.dev)
- 🐍 **Python SDK:** [sanctum-sdk-python](https://github.com/jwgale/sanctum-sdk-python)
- 📦 **Node.js SDK:** [sanctum-sdk-node](https://github.com/jwgale/sanctum-sdk-node)
- 🦀 **Rust SDK:** [sanctum-sdk-rust](https://github.com/jwgale/sanctum-sdk-rust)
- 🐛 **Issues:** [github.com/jwgale/sanctum-sdk-go/issues](https://github.com/jwgale/sanctum-sdk-go/issues)
