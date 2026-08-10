package decode

import (
	"strings"
	"testing"
)

func TestCalculateJA4_Synthetic(t *testing.T) {
	payload := []byte{
		0x16, 0x03, 0x01, 0x00, 0x32, // TLS Record Header
		0x01, 0x00, 0x00, 0x2e, // Handshake ClientHello
		0x03, 0x03, // Handshake Version 0x0303 (TLS 1.2)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // Session ID Length = 0
		0x00, 0x02, // Cipher Suites Length = 2
		0x00, 0x2f, // Cipher Suite
		0x01, 0x00, // Compression
		0x00, 0x00, // Extensions
	}

	result, ok := CalculateJA4(payload)
	if !ok {
		t.Fatalf("Failed to calculate JA4 from synthetic payload")
	}

	if !strings.HasPrefix(result.JA4String, "t12i010000_") {
		t.Errorf("Expected JA4 string prefix 't12i010000_', got '%s'", result.JA4String)
	}

	// Determinism test
	result2, _ := CalculateJA4(payload)
	if result.JA4String != result2.JA4String {
		t.Errorf("Determinism check failed: JA4 strings differ (%s vs %s)", result.JA4String, result2.JA4String)
	}
}
