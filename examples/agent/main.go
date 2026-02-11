package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"

	sanctum "github.com/jwgale/sanctum-sdk-go"
)

func main() {
	ctx := context.Background()

	client, err := sanctum.NewTCPClient("127.0.0.1:9090")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Load private key (in production, load from secure storage)
	keyHex := "your-128-hex-char-ed25519-private-key-here-00000000000000000000000000000000"
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatal("invalid key hex:", err)
	}
	privateKey := ed25519.PrivateKey(keyBytes)

	if err := client.Authenticate(ctx, "my-agent", privateKey); err != nil {
		log.Fatal("auth failed:", err)
	}
	fmt.Println("Authenticated!")

	result, err := client.Use(ctx, "api/openai", "chat.completions", map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]string{{"role": "user", "content": "Hello!"}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Use result: success=%v\n", result.Success)
}
