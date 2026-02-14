package main

import (
	"fmt"
	"log"
	"os"

	sanctum "github.com/SanctumSec/sanctum-sdk-go"
)

func main() {
	vaultPath := os.Args[1]
	passphrase := []byte(os.Args[2])

	// Initialize a new vault
	vault, err := sanctum.Init(vaultPath, passphrase)
	if err != nil {
		log.Fatal(err)
	}
	defer vault.Close()

	// Store a credential
	if err := vault.Store("api-key", []byte("sk-secret-123"), "my-agent", ""); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Stored credential: api-key")

	// Retrieve it
	secret, err := vault.Retrieve("api-key", "my-agent")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Retrieved: %s\n", secret)

	// Check audit log
	logJSON, err := vault.AuditLog("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Audit log: %s\n", logJSON)
}
