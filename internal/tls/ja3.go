package tls

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// WellKnownJA3 maps standard JA3 MD5 hashes to human-readable client identification labels.
var WellKnownJA3 = map[string]string{
	"cd2dde6459319854499d3910c2269a8b": "curl / libcurl",
	"b323091232d556d4e201b120d694da5c": "Go net/http Client",
	"6734f37431670b3ab4292b8f60a29984": "Google Chrome (Desktop)",
	"04666f2c31c77f0a8d67280d96d2ff86": "Python urllib / requests",
	"e7ed67db2926c10e231664e5b7e81281": "Firefox Browser",
	"9e49c717034c44e99990e6ff05f56475": "Safari / iOS WebKit",
}

// JA3Result encapsulates parsed TLS ClientHello fingerprint fields.
type JA3Result struct {
	RawString string
	Hash      string
	Label     string
}

// IsGREASE checks if a uint16 value is a TLS GREASE (Generate Random Extensions And Sustain Extensibility) value.
func IsGREASE(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a
}

// ParseClientHello parses raw TCP application payload bytes for a TLS ClientHello record.
// Returns JA3Result containing the raw fingerprint string, MD5 hash, and matched client label.
func ParseClientHello(payload []byte) (JA3Result, bool) {
	if len(payload) < 45 {
		return JA3Result{}, false
	}

	// 1. Check TLS Record Header: ContentType == 0x16 (Handshake), Version == 0x030x (TLS)
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return JA3Result{}, false
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return JA3Result{}, false
	}

	handshakePayload := payload[5 : 5+recordLen]
	if len(handshakePayload) < 38 {
		return JA3Result{}, false
	}

	// 2. Check Handshake Type == 0x01 (ClientHello)
	if handshakePayload[0] != 0x01 {
		return JA3Result{}, false
	}

	// Extract Handshake Version
	version := binary.BigEndian.Uint16(handshakePayload[4:6])

	// Skip Random (32 bytes) -> offset = 38
	offset := 38

	// Skip Session ID
	if offset >= len(handshakePayload) {
		return JA3Result{}, false
	}
	sessionIDLen := int(handshakePayload[offset])
	offset += 1 + sessionIDLen

	// Parse Cipher Suites
	if offset+2 > len(handshakePayload) {
		return JA3Result{}, false
	}
	cipherLen := int(binary.BigEndian.Uint16(handshakePayload[offset : offset+2]))
	offset += 2

	if offset+cipherLen > len(handshakePayload) {
		return JA3Result{}, false
	}

	var ciphers []string
	for i := 0; i < cipherLen; i += 2 {
		c := binary.BigEndian.Uint16(handshakePayload[offset+i : offset+i+2])
		if !IsGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%d", c))
		}
	}
	offset += cipherLen

	// Parse Compression Methods
	if offset+1 > len(handshakePayload) {
		return JA3Result{}, false
	}
	compLen := int(handshakePayload[offset])
	offset += 1 + compLen

	// Parse Extensions
	var extensions []string
	var curves []string
	var points []string

	if offset+2 <= len(handshakePayload) {
		extLen := int(binary.BigEndian.Uint16(handshakePayload[offset : offset+2]))
		offset += 2

		endExt := offset + extLen
		if endExt > len(handshakePayload) {
			endExt = len(handshakePayload)
		}

		for offset+4 <= endExt {
			extType := binary.BigEndian.Uint16(handshakePayload[offset : offset+2])
			extDataLen := int(binary.BigEndian.Uint16(handshakePayload[offset+2 : offset+4]))
			offset += 4

			if !IsGREASE(extType) {
				extensions = append(extensions, fmt.Sprintf("%d", extType))
			}

			if offset+extDataLen > endExt {
				break
			}

			extData := handshakePayload[offset : offset+extDataLen]

			// Extension 10: Supported Groups / Elliptic Curves
			if extType == 10 && len(extData) >= 2 {
				curvesLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+curvesLen {
					for cIdx := 0; cIdx < curvesLen; cIdx += 2 {
						curve := binary.BigEndian.Uint16(extData[2+cIdx : 4+cIdx])
						if !IsGREASE(curve) {
							curves = append(curves, fmt.Sprintf("%d", curve))
						}
					}
				}
			}

			// Extension 11: EC Point Formats
			if extType == 11 && len(extData) >= 1 {
				pLen := int(extData[0])
				if len(extData) >= 1+pLen {
					for pIdx := 0; pIdx < pLen; pIdx++ {
						points = append(points, fmt.Sprintf("%d", extData[1+pIdx]))
					}
				}
			}

			offset += extDataLen
		}
	}

	// 3. Format JA3 raw string: Version,Ciphers,Extensions,Curves,Points
	rawJA3 := fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)

	// 4. Calculate MD5 Hash
	hashBytes := md5.Sum([]byte(rawJA3))
	hashHex := hex.EncodeToString(hashBytes[:])

	label, known := WellKnownJA3[hashHex]
	if !known {
		label = "Unknown TLS Client"
	}

	return JA3Result{
		RawString: rawJA3,
		Hash:      hashHex,
		Label:     label,
	}, true
}
