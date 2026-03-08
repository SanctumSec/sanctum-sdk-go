// Package sanctum provides Go bindings for the Sanctum credential vault
// via CGo wrapping the sanctum-ffi C library.
package sanctum

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -lsanctum_ffi
#include "sanctum.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

// Version is the SDK version. Matches the SanctumAI release tag.
const Version = "0.4.0"

// Vault wraps an opaque SanctumVault handle from the FFI layer.
type Vault struct {
	ptr *C.SanctumVault
}

// Init creates and initializes a new vault at the given path with the supplied passphrase.
func Init(path string, passphrase []byte) (*Vault, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ptr := C.sanctum_vault_init(
		cPath,
		(*C.uint8_t)(unsafe.Pointer(&passphrase[0])),
		C.uintptr_t(len(passphrase)),
	)
	if ptr == nil {
		msg := lastErrorMessage()
		if msg != "" {
			return nil, errors.New("sanctum: init failed: " + msg)
		}
		return nil, errors.New("sanctum: init failed")
	}
	return &Vault{ptr: ptr}, nil
}

// Open unlocks an existing vault at the given path with the supplied passphrase.
func Open(path string, passphrase []byte) (*Vault, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ptr := C.sanctum_vault_open(
		cPath,
		(*C.uint8_t)(unsafe.Pointer(&passphrase[0])),
		C.uintptr_t(len(passphrase)),
	)
	if ptr == nil {
		msg := lastErrorMessage()
		if msg != "" {
			return nil, errors.New("sanctum: open failed: " + msg)
		}
		return nil, errors.New("sanctum: open failed")
	}
	return &Vault{ptr: ptr}, nil
}

// Close frees the underlying vault handle. Safe to call multiple times.
func (v *Vault) Close() {
	if v.ptr != nil {
		C.sanctum_vault_free(v.ptr)
		v.ptr = nil
	}
}

// Store saves a credential in the vault.
// policyJSON may be empty for no policy; agentID identifies the storing agent.
func (v *Vault) Store(name string, secret []byte, agentID string, policyJSON string) error {
	if v.ptr == nil {
		return errors.New("sanctum: vault is closed")
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cAgent := C.CString(agentID)
	defer C.free(unsafe.Pointer(cAgent))

	var cPolicy *C.char
	if policyJSON != "" {
		cPolicy = C.CString(policyJSON)
		defer C.free(unsafe.Pointer(cPolicy))
	}

	rc := C.sanctum_vault_store(
		v.ptr,
		cName,
		(*C.uint8_t)(unsafe.Pointer(&secret[0])),
		C.uintptr_t(len(secret)),
		cAgent,
		cPolicy,
	)
	return resultToError(rc)
}

// Retrieve fetches a credential's secret bytes from the vault.
func (v *Vault) Retrieve(name string, agentID string) ([]byte, error) {
	if v.ptr == nil {
		return nil, errors.New("sanctum: vault is closed")
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cAgent := C.CString(agentID)
	defer C.free(unsafe.Pointer(cAgent))

	// First call to get required size.
	var needed C.uintptr_t
	rc := C.sanctum_vault_retrieve(v.ptr, cName, cAgent, nil, &needed)
	if rc != C.BUFFER_TOO_SMALL && rc != C.OK {
		return nil, resultToError(rc)
	}
	if needed == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, int(needed))
	outLen := needed
	rc = C.sanctum_vault_retrieve(
		v.ptr, cName, cAgent,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		&outLen,
	)
	if err := resultToError(rc); err != nil {
		return nil, err
	}
	return buf[:int(outLen)], nil
}

// CheckPolicy checks whether an agent is allowed to retrieve a credential.
// Returns nil if allowed, ErrAccessDenied if not.
func (v *Vault) CheckPolicy(name string, agentID string) error {
	if v.ptr == nil {
		return errors.New("sanctum: vault is closed")
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cAgent := C.CString(agentID)
	defer C.free(unsafe.Pointer(cAgent))

	rc := C.sanctum_vault_check_policy(v.ptr, cName, cAgent)
	return resultToError(rc)
}

// AuditLog returns the audit log as a JSON string.
// If agentIDFilter is non-empty, only entries for that agent are returned.
func (v *Vault) AuditLog(agentIDFilter string) (string, error) {
	if v.ptr == nil {
		return "", errors.New("sanctum: vault is closed")
	}

	var cFilter *C.char
	if agentIDFilter != "" {
		cFilter = C.CString(agentIDFilter)
		defer C.free(unsafe.Pointer(cFilter))
	}

	// First call to get required size.
	var needed C.uintptr_t
	rc := C.sanctum_vault_audit_log(v.ptr, cFilter, nil, &needed)
	if rc != C.BUFFER_TOO_SMALL && rc != C.OK {
		return "", resultToError(rc)
	}
	if needed == 0 {
		return "[]", nil
	}

	buf := make([]byte, int(needed)+1) // +1 for NUL
	outLen := C.uintptr_t(len(buf))
	rc = C.sanctum_vault_audit_log(
		v.ptr, cFilter,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		&outLen,
	)
	if err := resultToError(rc); err != nil {
		return "", err
	}
	return string(buf[:int(outLen)]), nil
}

// Delete removes a credential from the vault.
func (v *Vault) Delete(name string, agentID string) error {
	if v.ptr == nil {
		return errors.New("sanctum: vault is closed")
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cAgent := C.CString(agentID)
	defer C.free(unsafe.Pointer(cAgent))

	rc := C.sanctum_vault_delete(v.ptr, cName, cAgent)
	return resultToError(rc)
}

// ListCredentials returns credential paths as a JSON array string.
func (v *Vault) ListCredentials(agentID string) (string, error) {
	if v.ptr == nil {
		return "", errors.New("sanctum: vault is closed")
	}

	cAgent := C.CString(agentID)
	defer C.free(unsafe.Pointer(cAgent))

	// First call to get required size.
	var needed C.uintptr_t
	rc := C.sanctum_vault_list_credentials(v.ptr, cAgent, nil, &needed)
	if rc != C.BUFFER_TOO_SMALL && rc != C.OK {
		return "", resultToError(rc)
	}
	if needed == 0 {
		return "[]", nil
	}

	buf := make([]byte, int(needed)+1)
	outLen := C.uintptr_t(len(buf))
	rc = C.sanctum_vault_list_credentials(
		v.ptr, cAgent,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		&outLen,
	)
	if err := resultToError(rc); err != nil {
		return "", err
	}
	return string(buf[:int(outLen)]), nil
}

// UseCredential performs an operation using a credential without exposing the
// secret to the caller. This is the recommended way for agents to use
// credentials — the vault acts as a proxy so the agent never sees raw secrets.
//
// Supported operations:
//   - "http_request" — make an HTTP request with the credential injected
//   - "http_header"  — get an HTTP authorization header value
//   - "sign"         — sign data (e.g. HMAC)
//   - "encrypt"      — encrypt data
//   - "decrypt"      — decrypt data
//
// params is a map of operation-specific parameters (serialized to JSON internally).
// Returns the operation result as a map parsed from the JSON response.
func (v *Vault) UseCredential(name string, agentID string, operation string, params map[string]interface{}) (map[string]interface{}, error) {
	if v.ptr == nil {
		return nil, errors.New("sanctum: vault is closed")
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, errors.New("sanctum: failed to marshal params: " + err.Error())
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cAgent := C.CString(agentID)
	defer C.free(unsafe.Pointer(cAgent))
	cOp := C.CString(operation)
	defer C.free(unsafe.Pointer(cOp))
	cParams := C.CString(string(paramsJSON))
	defer C.free(unsafe.Pointer(cParams))

	// First call to get required size.
	var needed C.uintptr_t
	rc := C.sanctum_vault_use_credential(v.ptr, cName, cAgent, cOp, cParams, nil, &needed)
	if rc != C.BUFFER_TOO_SMALL && rc != C.OK {
		return nil, resultToError(rc)
	}
	if needed == 0 {
		return map[string]interface{}{}, nil
	}

	buf := make([]byte, int(needed)+1)
	outLen := C.uintptr_t(len(buf))
	rc = C.sanctum_vault_use_credential(
		v.ptr, cName, cAgent, cOp, cParams,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		&outLen,
	)
	if err := resultToError(rc); err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf[:int(outLen)], &result); err != nil {
		return nil, errors.New("sanctum: failed to parse response: " + err.Error())
	}
	return result, nil
}
