package sanctum

/*
#include "sanctum.h"
*/
import "C"
import (
	"errors"
	"fmt"
)

var (
	ErrNullPointer    = errors.New("sanctum: null pointer")
	ErrInvalidUTF8    = errors.New("sanctum: invalid UTF-8")
	ErrNotInitialized = errors.New("sanctum: vault not initialized")
	ErrAccessDenied   = errors.New("sanctum: access denied")
	ErrNotFound       = errors.New("sanctum: credential not found")
	ErrCrypto         = errors.New("sanctum: cryptographic error")
	ErrBufferTooSmall = errors.New("sanctum: buffer too small")
	ErrJSON           = errors.New("sanctum: JSON error")
	ErrPanic          = errors.New("sanctum: panic caught at FFI boundary")
	ErrUnknown        = errors.New("sanctum: unknown error")
)

// resultToError converts a SanctumResult code to a Go error.
// Returns nil for OK (0).
func resultToError(code C.SanctumResult) error {
	switch code {
	case C.OK:
		return nil
	case C.NULL_POINTER:
		return ErrNullPointer
	case C.INVALID_UTF8:
		return ErrInvalidUTF8
	case C.NOT_INITIALIZED:
		return ErrNotInitialized
	case C.ACCESS_DENIED:
		return ErrAccessDenied
	case C.NOT_FOUND:
		return ErrNotFound
	case C.CRYPTO_ERROR:
		return ErrCrypto
	case C.BUFFER_TOO_SMALL:
		return ErrBufferTooSmall
	case C.JSON_ERROR:
		return ErrJSON
	case C.PANIC:
		return ErrPanic
	default:
		return fmt.Errorf("sanctum: error code %d", code)
	}
}

// lastErrorMessage returns the thread-local error string from the FFI layer.
func lastErrorMessage() string {
	p := C.sanctum_error_message()
	if p == nil {
		return ""
	}
	return C.GoString(p)
}
