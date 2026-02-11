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
	fmt.Println("Available credentials:")
	for _, c := range creds {
		fmt.Printf("  - %s\n", c.Path)
	}

	cred, err := client.Retrieve(ctx, "database/primary", 300)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Retrieved: %s (lease: %s)\n", cred.Path, cred.LeaseID)

	if err := client.ReleaseLease(ctx, cred.LeaseID); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Lease released.")
}
