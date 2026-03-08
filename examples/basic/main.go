package main

import (
	"fmt"
	"log"
	"os"

	sanctum "github.com/SanctumSec/sanctum-sdk-go"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <vault-path> <passphrase>\n", os.Args[0])
		os.Exit(1)
	}
	vaultPath := os.Args[1]
	passphrase := []byte(os.Args[2])

	fmt.Println("sanctum-sdk-go version:", sanctum.Version)

	// Initialize a new vault
	vault, err := sanctum.Init(vaultPath, passphrase)
	if err != nil {
		log.Fatal(err)
	}
	defer vault.Close()

	// Store a credential
	if err := vault.Store("openai/api-key", []byte("sk-secret-123"), "my-agent", ""); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Stored credential: openai/api-key")

	// Use the credential to proxy an HTTP request (recommended pattern)
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
	fmt.Printf("Response status: %v\n", result["status"])

	// List all credentials
	list, err := vault.ListCredentials("my-agent")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Credentials: %s\n", list)

	// Check audit log
	logJSON, err := vault.AuditLog("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Audit log: %s\n", logJSON)
}
