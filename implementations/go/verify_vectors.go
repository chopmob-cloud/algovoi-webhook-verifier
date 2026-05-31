// AlgoVoi webhook-verifier cross-validation — Go implementation
// Usage: go run verify_vectors.go ../../vectors
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var sigRe = regexp.MustCompile(`^t=(\d+),v1=([0-9a-f]{64})(?:,v2=([0-9a-f]{96}))?$`)

// HKDF-SHA256: Extract + Expand (RFC 5869)
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	// Extract
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	// Expand
	var okm []byte
	prev := []byte{}
	for i := 1; len(okm) < length; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length]
}

func computeSigs(secret string, ts int64, body []byte) (string, string) {
	secretBytes := []byte(secret)
	tsPrefix := []byte(strconv.FormatInt(ts, 10) + ".")
	signed := append(tsPrefix, body...)

	// v1: HMAC-SHA256(secret, signed)
	mac1 := hmac.New(sha256.New, secretBytes)
	mac1.Write(signed)
	v1 := hex.EncodeToString(mac1.Sum(nil))

	// v2_key: HKDF-SHA256(secret, salt, info, 48)
	v2Key := hkdfSHA256(
		secretBytes,
		[]byte("algovoi-webhook-v2-pqc"),
		[]byte("hmac-sha384-outbound"),
		48,
	)

	// v2: HMAC-SHA384(v2_key, signed)
	mac2 := hmac.New(sha512.New384, v2Key)
	mac2.Write(signed)
	v2 := hex.EncodeToString(mac2.Sum(nil))

	return v1, v2
}

type Fixture struct {
	Description     string `json:"description"`
	Secret          string `json:"secret"`
	Timestamp       int64  `json:"timestamp"`
	Body            string `json:"body"`
	SignatureHeader  string `json:"signature_header"`
	Expected        string `json:"expected"`
	ErrorCode       string `json:"error_code"`
	Tolerance       int    `json:"tolerance"`
	FakeNow         int64  `json:"fake_now"`
}

func verify(f Fixture) (string, error) {
	hdr := strings.TrimSpace(f.SignatureHeader)
	if hdr == "" {
		return "MISSING_SIGNATURE", nil
	}

	m := sigRe.FindStringSubmatch(hdr)
	if m == nil {
		return "MALFORMED_SIGNATURE", nil
	}

	ts, _ := strconv.ParseInt(m[1], 10, 64)
	receivedV1 := m[2]
	receivedV2 := ""
	if len(m) > 3 {
		receivedV2 = m[3]
	}

	// Staleness check (skipped when tolerance == 0 or fake_now not set)
	// For cross-validation we always use tolerance=0
	_ = ts

	body := []byte(f.Body)
	expectedV1, expectedV2 := computeSigs(f.Secret, f.Timestamp, body)

	v1Ok := hmac.Equal([]byte(receivedV1), []byte(expectedV1))
	v2Ok := true
	if receivedV2 != "" {
		v2Ok = hmac.Equal([]byte(receivedV2), []byte(expectedV2))
	}

	// For stale vectors, re-check with fake_now
	if f.FakeNow > 0 && f.Tolerance > 0 {
		age := f.Timestamp - f.FakeNow
		if age < 0 {
			age = -age
		}
		if age > int64(f.Tolerance) {
			return "STALE_SIGNATURE", nil
		}
	}

	if !v1Ok || !v2Ok {
		return "INVALID_SIGNATURE", nil
	}

	// JSON parse
	var event map[string]interface{}
	if err := json.Unmarshal(body, &event); err != nil {
		return "INVALID_PAYLOAD", nil
	}
	if event == nil {
		return "INVALID_PAYLOAD", nil
	}

	// Event type check
	eventType, _ := event["type"].(string)
	if eventType != "payment.confirmed" {
		return "UNKNOWN_EVENT_TYPE", nil
	}

	return "ok", nil
}

func runDir(dir string) (int, int) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(entries) == 0 {
		return 0, 0
	}

	pass, total := 0, 0
	for _, path := range entries {
		data, _ := os.ReadFile(path)
		var f Fixture
		json.Unmarshal(data, &f)

		result, _ := verify(f)

		var got string
		if result == "ok" {
			got = "ok"
		} else {
			got = result
		}

		var want string
		if f.Expected == "ok" {
			want = "ok"
		} else {
			want = f.ErrorCode
		}

		name := filepath.Base(path)
		total++
		if got == want {
			pass++
			fmt.Printf("  PASS  %s\n", name)
		} else {
			fmt.Printf("  FAIL  %s  (want=%s got=%s)\n", name, want, got)
		}
	}
	return pass, total
}

func main() {
	vectorsRoot := "../../vectors"
	if len(os.Args) > 1 {
		vectorsRoot = os.Args[1]
	}

	fmt.Println("AlgoVoi webhook-verifier — Go cross-validation")
	fmt.Println()

	fmt.Println("valid/")
	vp, vt := runDir(filepath.Join(vectorsRoot, "valid"))

	fmt.Println("invalid/")
	ip, it := runDir(filepath.Join(vectorsRoot, "invalid"))

	total := vt + it
	pass := vp + ip
	fmt.Printf("\nResult: %d/%d\n", pass, total)
	if pass != total {
		os.Exit(1)
	}
}
