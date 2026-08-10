package tls

import (
	"testing"
)

func TestParseClientHello_Synthetic(t *testing.T) {
	// Synthesize a minimal valid TLS 1.2 ClientHello record payload
	payload := []byte{
		0x16, 0x03, 0x01, 0x00, 0x32, // Record Header (0x16 Handshake, 0x0301 TLS 1.0 record, len=50)
		0x01, 0x00, 0x00, 0x2e, // Handshake Header (0x01 ClientHello, len=46)
		0x03, 0x03, // Handshake Version 0x0303 (TLS 1.2 -> 771)
		// 32 bytes Random:
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // Session ID Length = 0
		0x00, 0x02, // Cipher Suites Length = 2
		0x00, 0x2f, // Cipher Suite TLS_RSA_WITH_AES_128_CBC_SHA (47)
		0x01, 0x00, // Compression Methods (len=1, null)
		0x00, 0x00, // Extensions Length = 0
	}

	result, ok := ParseClientHello(payload)
	if !ok {
		t.Fatalf("Failed to parse valid synthetic TLS ClientHello")
	}

	if !result.ok() && result.Hash == "" {
		t.Errorf("Expected valid JA3 hash result")
	}

	if result.RawString != "771,47,,," {
		t.Errorf("Expected raw JA3 string '771,47,,,', got '%s'", result.RawString)
	}

	// Determinism test: re-parsing same payload must yield identical hash
	result2, _ := ParseClientHello(payload)
	if result.Hash != result2.Hash {
		t.Errorf("Determinism check failed: hashes differ (%s vs %s)", result.Hash, result2.Hash)
	}
}

func (res JA3Result) ok() bool {
	return len(res.Hash) == 32
}
