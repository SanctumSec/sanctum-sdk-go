package sanctum

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const maxFrameSize = 16 * 1024 * 1024 // 16 MB

// writeFrame writes a length-prefixed JSON-RPC request.
func writeFrame(w io.Writer, req *RpcRequest) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	length := uint32(len(payload))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// readFrame reads a length-prefixed JSON-RPC response.
func readFrame(r io.Reader) (*RpcResponse, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if length > maxFrameSize {
		return nil, &ProtocolError{Message: fmt.Sprintf("frame too large: %d bytes", length)}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	var resp RpcResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &resp, nil
}
