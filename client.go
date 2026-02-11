// Package sanctum provides a Go SDK for communicating with a SanctumAI vault.
package sanctum

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Client communicates with a SanctumAI vault over Unix socket or TCP.
type Client struct {
	conn   net.Conn
	mu     sync.Mutex
	nextID atomic.Uint64
}

// NewClient connects to a SanctumAI vault via Unix socket.
func NewClient(socketPath string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect unix %s: %w", socketPath, err)
	}
	c := &Client{conn: conn}
	c.nextID.Store(1)
	return c, nil
}

// NewTCPClient connects to a SanctumAI vault via TCP.
func NewTCPClient(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect tcp %s: %w", addr, err)
	}
	c := &Client{conn: conn}
	c.nextID.Store(1)
	return c, nil
}

// Close closes the connection to the vault.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}

	req := &RpcRequest{
		ID:     c.nextID.Add(1) - 1,
		Method: method,
		Params: paramsBytes,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		defer c.conn.SetDeadline(time.Time{}) //nolint:errcheck
	}

	if err := writeFrame(c.conn, req); err != nil {
		return nil, err
	}

	resp, err := readFrame(c.conn)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		var vaultErr VaultError
		if err := json.Unmarshal(resp.Error, &vaultErr); err != nil {
			return nil, &ProtocolError{Message: "failed to parse error response"}
		}
		return nil, &vaultErr
	}

	return resp.Result, nil
}

// Authenticate performs Ed25519 challenge-response authentication.
func (c *Client) Authenticate(ctx context.Context, agentName string, privateKey ed25519.PrivateKey) error {
	// Step 1: Request challenge
	result, err := c.call(ctx, "auth.challenge", map[string]string{"agent": agentName})
	if err != nil {
		return fmt.Errorf("auth challenge: %w", err)
	}

	var challenge authChallenge
	if err := json.Unmarshal(result, &challenge); err != nil {
		return fmt.Errorf("parse challenge: %w", err)
	}

	// Step 2: Sign challenge
	challengeBytes, err := hex.DecodeString(challenge.Challenge)
	if err != nil {
		return fmt.Errorf("decode challenge hex: %w", err)
	}
	signature := ed25519.Sign(privateKey, challengeBytes)

	// Step 3: Submit signature
	verifyResult, err := c.call(ctx, "auth.verify", map[string]string{
		"agent":     agentName,
		"signature": hex.EncodeToString(signature),
	})
	if err != nil {
		return fmt.Errorf("auth verify: %w", err)
	}

	var auth authResult
	if err := json.Unmarshal(verifyResult, &auth); err != nil {
		return fmt.Errorf("parse auth result: %w", err)
	}
	if !auth.Authenticated {
		return fmt.Errorf("authentication rejected by server")
	}
	return nil
}

// Retrieve gets a credential by path with the given TTL in seconds.
func (c *Client) Retrieve(ctx context.Context, path string, ttl int) (*Credential, error) {
	result, err := c.call(ctx, "credential.retrieve", map[string]interface{}{
		"path": path,
		"ttl":  ttl,
	})
	if err != nil {
		return nil, err
	}
	var cred Credential
	if err := json.Unmarshal(result, &cred); err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}
	return &cred, nil
}

// List returns all available credentials.
func (c *Client) List(ctx context.Context) ([]CredentialInfo, error) {
	result, err := c.call(ctx, "credential.list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var creds []CredentialInfo
	if err := json.Unmarshal(result, &creds); err != nil {
		return nil, fmt.Errorf("parse credential list: %w", err)
	}
	return creds, nil
}

// ReleaseLease releases a credential lease.
func (c *Client) ReleaseLease(ctx context.Context, leaseID string) error {
	_, err := c.call(ctx, "lease.release", map[string]string{"lease_id": leaseID})
	return err
}

// Use performs a use-not-retrieve operation on a credential.
func (c *Client) Use(ctx context.Context, path, operation string, params map[string]interface{}) (*UseResult, error) {
	result, err := c.call(ctx, "credential.use", map[string]interface{}{
		"path":      path,
		"operation": operation,
		"params":    params,
	})
	if err != nil {
		return nil, err
	}
	var ur UseResult
	if err := json.Unmarshal(result, &ur); err != nil {
		return nil, fmt.Errorf("parse use result: %w", err)
	}
	return &ur, nil
}
