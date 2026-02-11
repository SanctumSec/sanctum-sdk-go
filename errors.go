package sanctum

import (
	"encoding/json"
	"fmt"
)

// Error codes returned by the SanctumAI vault.
const (
	ErrAuthFailed         = "AUTH_FAILED"
	ErrAccessDenied       = "ACCESS_DENIED"
	ErrCredentialNotFound = "CREDENTIAL_NOT_FOUND"
	ErrVaultLocked        = "VAULT_LOCKED"
	ErrLeaseExpired       = "LEASE_EXPIRED"
	ErrRateLimited        = "RATE_LIMITED"
	ErrSessionExpired     = "SESSION_EXPIRED"
)

// VaultError is a structured error from the SanctumAI vault.
type VaultError struct {
	Code       string          `json:"code"`
	Message    string          `json:"message"`
	Detail     string          `json:"detail,omitempty"`
	Suggestion string          `json:"suggestion,omitempty"`
	DocsURL    string          `json:"docs_url,omitempty"`
	Context    json.RawMessage `json:"context,omitempty"`
}

func (e *VaultError) Error() string {
	s := fmt.Sprintf("[%s] %s", e.Code, e.Message)
	if e.Detail != "" {
		s += " — " + e.Detail
	}
	return s
}

// ProtocolError indicates a framing or protocol-level error.
type ProtocolError struct {
	Message string
}

func (e *ProtocolError) Error() string {
	return "protocol error: " + e.Message
}
