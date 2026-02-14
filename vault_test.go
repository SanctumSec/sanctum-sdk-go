package sanctum

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempVault(t *testing.T, pass []byte) *Vault {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Init(dir, pass)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestInitAndOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	pass := []byte("test-passphrase")

	v, err := Init(dir, pass)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	v.Close()

	v2, err := Open(dir, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	v2.Close()
}

func TestStoreAndRetrieve(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	secret := []byte("super-secret-value")
	if err := v.Store("api-key", secret, "agent-1", ""); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := v.Retrieve("api-key", "agent-1")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestRetrieveNotFound(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	_, err := v.Retrieve("nonexistent", "agent-1")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestCheckPolicy(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	// Store with a policy allowing only agent-1
	policy := `{"name":"test","principal":"agent:agent-1","resources":["restricted"],"actions":["retrieve"],"max_lease_ttl":3600,"conditions":{},"enabled":true}`
	if err := v.Store("restricted", []byte("secret"), "agent-1", policy); err != nil {
		t.Fatalf("Store: %v", err)
	}

	if err := v.CheckPolicy("restricted", "agent-1"); err != nil {
		t.Fatalf("CheckPolicy allowed agent: %v", err)
	}

	if err := v.CheckPolicy("restricted", "agent-2"); err != ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied for agent-2, got: %v", err)
	}
}

func TestAuditLog(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	if err := v.Store("key1", []byte("val"), "agent-1", ""); err != nil {
		t.Fatalf("Store: %v", err)
	}

	log, err := v.AuditLog("")
	if err != nil {
		t.Fatalf("AuditLog: %v", err)
	}
	if !strings.Contains(log, "agent-1") {
		t.Fatalf("audit log missing agent-1: %s", log)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Init(dir, []byte("correct"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	v.Close()

	_, err = Open(dir, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}

func TestClosedVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Init(dir, []byte("pass"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	v.Close()

	if err := v.Store("x", []byte("y"), "a", ""); err == nil {
		t.Fatal("expected error on closed vault")
	}
}

func TestDelete(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	if err := v.Store("to-delete", []byte("secret"), "agent-1", ""); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Verify it exists
	if _, err := v.Retrieve("to-delete", "agent-1"); err != nil {
		t.Fatalf("Retrieve before delete: %v", err)
	}

	// Delete it
	if err := v.Delete("to-delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify it's gone
	_, err := v.Retrieve("to-delete", "agent-1")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestListCredentials(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	// Empty vault
	list, err := v.ListCredentials()
	if err != nil {
		t.Fatalf("ListCredentials empty: %v", err)
	}
	if list != "[]" && list != "" {
		// Accept empty array or empty string
	}

	// Store some credentials
	if err := v.Store("key-a", []byte("val-a"), "agent-1", ""); err != nil {
		t.Fatalf("Store key-a: %v", err)
	}
	if err := v.Store("key-b", []byte("val-b"), "agent-2", ""); err != nil {
		t.Fatalf("Store key-b: %v", err)
	}

	list, err = v.ListCredentials()
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if !strings.Contains(list, "key-a") || !strings.Contains(list, "key-b") {
		t.Fatalf("ListCredentials missing keys: %s", list)
	}
}

func TestDeleteNotFound(t *testing.T) {
	v := tempVault(t, []byte("pass"))

	err := v.Delete("nonexistent")
	// Should either succeed silently or return ErrNotFound
	if err != nil && err != ErrNotFound {
		t.Fatalf("unexpected error deleting nonexistent: %v", err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
