package redact

import (
	"strings"
	"testing"
)

func TestPrivateKeyData(t *testing.T) {
	in := []byte(`{"keys":[{"privateKeyData":"-----BEGIN PRIVATE KEY-----\nabc\n"}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "BEGIN PRIVATE") {
		t.Fatal("private key leaked")
	}
}

func TestAPIKeyString(t *testing.T) {
	in := []byte(`{"keys":[{"name":"projects/p/locations/global/keys/abc","keyString":"AIzaSecret","restrictions":{}},{"name":"projects/p/locations/global/keys/empty","keyString":""}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "AIzaSecret") {
		t.Fatal("API key material leaked")
	}
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Fatalf("marker missing: %s", out)
	}
	if !strings.Contains(string(out), "projects/p/locations/global/keys/abc") {
		t.Fatalf("key name stripped: %s", out)
	}
}

func TestVPNSharedSecret(t *testing.T) {
	in := []byte(`{"vpnTunnels":[{"sharedSecret":"supersecret"}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "supersecret") {
		t.Fatal("PSK leaked")
	}
}
