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

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
