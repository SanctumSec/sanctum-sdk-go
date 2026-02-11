package sanctum

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestWriteReadFrame(t *testing.T) {
	params, _ := json.Marshal(map[string]string{"key": "value"})
	req := &RpcRequest{
		ID:     1,
		Method: "test.method",
		Params: params,
	}

	var buf bytes.Buffer
	if err := writeFrame(&buf, req); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	// Verify length prefix
	data := buf.Bytes()
	length := binary.BigEndian.Uint32(data[:4])
	if int(length) != len(data)-4 {
		t.Errorf("length prefix %d != payload size %d", length, len(data)-4)
	}

	// Write a response into a buffer and read it
	resp := &RpcResponse{
		ID:     1,
		Result: json.RawMessage(`{"ok":true}`),
	}
	respBytes, _ := json.Marshal(resp)
	var respBuf bytes.Buffer
	binary.Write(&respBuf, binary.BigEndian, uint32(len(respBytes)))
	respBuf.Write(respBytes)

	got, err := readFrame(&respBuf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.ID != 1 {
		t.Errorf("expected id 1, got %d", got.ID)
	}
	if got.Result == nil {
		t.Error("expected result, got nil")
	}
}

func TestVaultErrorFormat(t *testing.T) {
	err := &VaultError{
		Code:    ErrVaultLocked,
		Message: "Vault is sealed",
		Detail:  "Run unseal command first",
	}
	expected := "[VAULT_LOCKED] Vault is sealed — Run unseal command first"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestProtocolErrorFormat(t *testing.T) {
	err := &ProtocolError{Message: "frame too large"}
	if err.Error() != "protocol error: frame too large" {
		t.Errorf("unexpected: %s", err.Error())
	}
}
