package sanctum

import "encoding/json"

// RpcRequest represents a JSON-RPC request.
type RpcRequest struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// RpcResponse represents a JSON-RPC response.
type RpcResponse struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// Credential holds a retrieved credential with lease info.
type Credential struct {
	Path    string          `json:"path"`
	Value   json.RawMessage `json:"value"`
	LeaseID string          `json:"lease_id"`
	TTL     uint64          `json:"ttl"`
}

// CredentialInfo holds summary info for a credential.
type CredentialInfo struct {
	Path           string `json:"path"`
	CredentialType string `json:"type,omitempty"`
	Description    string `json:"description,omitempty"`
}

// UseResult holds the result of a use-not-retrieve operation.
type UseResult struct {
	Success bool            `json:"success"`
	Output  json.RawMessage `json:"output,omitempty"`
}

// AuthChallenge is returned by the server during authentication.
type authChallenge struct {
	Challenge string `json:"challenge"`
}

// AuthResult is returned after successful authentication.
type authResult struct {
	Authenticated bool   `json:"authenticated"`
	SessionID     string `json:"session_id,omitempty"`
}
