package decode

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed assets/ja4db.json
var ja4DBBytes []byte

var ja4Lookup map[string]string

func init() {
	ja4Lookup = make(map[string]string)
	if len(ja4DBBytes) > 0 {
		_ = json.Unmarshal(ja4DBBytes, &ja4Lookup)
	}
}

// JA4Result encapsulates parsed JA4 fingerprint metrics.
type JA4Result struct {
	JA4String string
	Label     string
	IsMalware bool
}

// IsGREASE4 checks if uint16 is a TLS GREASE value.
func IsGREASE4(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a
}

// CalculateJA4 parses a raw TLS ClientHello payload and generates the canonical JA4 fingerprint string.
func CalculateJA4(payload []byte) (JA4Result, bool) {
	if len(payload) < 45 {
		return JA4Result{}, false
	}

	// TLS Record Header: 0x16 (Handshake), 0x03 (TLS)
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return JA4Result{}, false
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return JA4Result{}, false
	}

	handshake := payload[5 : 5+recordLen]
	if len(handshake) < 38 || handshake[0] != 0x01 {
		return JA4Result{}, false
	}

	// 1. Version Determination
	handshakeVersion := binary.BigEndian.Uint16(handshake[4:6])
	tlsVersionStr := "12"
	switch handshakeVersion {
	case 0x0304:
		tlsVersionStr = "13"
	case 0x0303:
		tlsVersionStr = "12"
	case 0x0302:
		tlsVersionStr = "11"
	case 0x0301:
		tlsVersionStr = "10"
	}

	offset := 38

	// Skip Session ID
	if offset >= len(handshake) {
		return JA4Result{}, false
	}
	sessionIDLen := int(handshake[offset])
	offset += 1 + sessionIDLen

	// Parse Ciphers
	if offset+2 > len(handshake) {
		return JA4Result{}, false
	}
	cipherLen := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
	offset += 2

	if offset+cipherLen > len(handshake) {
		return JA4Result{}, false
	}

	var rawCiphers []uint16
	for i := 0; i < cipherLen; i += 2 {
		c := binary.BigEndian.Uint16(handshake[offset+i : offset+i+2])
		if !IsGREASE4(c) {
			rawCiphers = append(rawCiphers, c)
		}
	}
	offset += cipherLen

	// Skip Compression
	if offset+1 > len(handshake) {
		return JA4Result{}, false
	}
	compLen := int(handshake[offset])
	offset += 1 + compLen

	// Parse Extensions
	hasSNI := false
	alpnStr := "00"
	var rawExtensions []uint16
	var sigAlgs []uint16

	if offset+2 <= len(handshake) {
		extLen := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
		offset += 2

		endExt := offset + extLen
		if endExt > len(handshake) {
			endExt = len(handshake)
		}

		for offset+4 <= endExt {
			extType := binary.BigEndian.Uint16(handshake[offset : offset+2])
			extDataLen := int(binary.BigEndian.Uint16(handshake[offset+2 : offset+4]))
			offset += 4

			if !IsGREASE4(extType) {
				rawExtensions = append(rawExtensions, extType)
			}

			if offset+extDataLen > endExt {
				break
			}

			extData := handshake[offset : offset+extDataLen]

			// Extension 0x0000: SNI
			if extType == 0x0000 {
				hasSNI = true
			}

			// Extension 0x0010: ALPN
			if extType == 0x0010 && len(extData) >= 2 {
				alpnListLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+alpnListLen && alpnListLen > 1 {
					firstStrLen := int(extData[2])
					if len(extData) >= 3+firstStrLen && firstStrLen > 0 {
						alpnVal := string(extData[3 : 3+firstStrLen])
						if len(alpnVal) >= 2 {
							alpnStr = string(alpnVal[0]) + string(alpnVal[len(alpnVal)-1])
						} else if len(alpnVal) == 1 {
							alpnStr = string(alpnVal[0]) + string(alpnVal[0])
						}
					}
				}
			}

			// Extension 0x002b: Supported Versions
			if extType == 0x002b && len(extData) >= 1 {
				vLen := int(extData[0])
				if len(extData) >= 1+vLen {
					for vIdx := 0; vIdx < vLen; vIdx += 2 {
						ver := binary.BigEndian.Uint16(extData[1+vIdx : 3+vIdx])
						if ver == 0x0304 {
							tlsVersionStr = "13"
						}
					}
				}
			}

			// Extension 0x000d: Signature Algorithms
			if extType == 0x000d && len(extData) >= 2 {
				sigLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+sigLen {
					for sIdx := 0; sIdx < sigLen; sIdx += 2 {
						sa := binary.BigEndian.Uint16(extData[2+sIdx : 4+sIdx])
						if !IsGREASE4(sa) {
							sigAlgs = append(sigAlgs, sa)
						}
					}
				}
			}

			offset += extDataLen
		}
	}

	// Construct Part 1: [t][Version][SNI][CipherCount][ExtCount][ALPN]
	sniStr := "i"
	if hasSNI {
		sniStr = "d"
	}

	part1 := fmt.Sprintf("t%s%s%02d%02d%s",
		tlsVersionStr,
		sniStr,
		minVal(len(rawCiphers), 99),
		minVal(len(rawExtensions), 99),
		alpnStr,
	)

	// Construct Part 2: Hex SHA256 of sorted ciphers
	sortUint16s(rawCiphers)
	var cipherHex []string
	for _, c := range rawCiphers {
		cipherHex = append(cipherHex, fmt.Sprintf("%04x", c))
	}
	part2 := truncatedSHA256(strings.Join(cipherHex, ","))

	// Construct Part 3: Hex SHA256 of sorted extensions + sig algs
	sortUint16s(rawExtensions)
	var extHex []string
	for _, e := range rawExtensions {
		extHex = append(extHex, fmt.Sprintf("%04x", e))
	}
	if len(sigAlgs) > 0 {
		var sigHex []string
		for _, s := range sigAlgs {
			sigHex = append(sigHex, fmt.Sprintf("%04x", s))
		}
		extHex = append(extHex, "_"+strings.Join(sigHex, ","))
	}
	part3 := truncatedSHA256(strings.Join(extHex, ","))

	ja4String := fmt.Sprintf("%s_%s_%s", part1, part2, part3)

	label, known := ja4Lookup[ja4String]
	isMalware := false
	if !known {
		label = "Unknown TLS Client"
	} else if strings.Contains(strings.ToLower(label), "beacon") || strings.Contains(strings.ToLower(label), "c2") || strings.Contains(strings.ToLower(label), "malware") || strings.Contains(strings.ToLower(label), "stealer") {
		isMalware = true
	}

	return JA4Result{
		JA4String: ja4String,
		Label:     label,
		IsMalware: isMalware,
	}, true
}

func minVal(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sortUint16s(slice []uint16) {
	sort.Slice(slice, func(i, j int) bool {
		return slice[i] < slice[j]
	})
}

func truncatedSHA256(input string) string {
	if input == "" {
		return "000000000000"
	}
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])[:12]
}
