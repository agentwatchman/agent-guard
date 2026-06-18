package scan

import (
	"testing"

	"agentguard/internal/types"
)

// Secret scanner catches common secret shapes and a secret file attachment.
func TestScan(t *testing.T) {
	cases := []struct {
		name string
		req  types.ScanRequest
		want bool
	}{
		{"openai key in prompt", types.ScanRequest{Text: "use sk-abcdef0123456789ABCDEF01 please"}, true},
		{"aws key id", types.ScanRequest{Text: "AKIAIOSFODNN7EXAMPLE"}, true},
		{"private key block", types.ScanRequest{Text: "-----BEGIN RSA PRIVATE KEY-----\nMII..."}, true},
		{"secret assignment high entropy", types.ScanRequest{Text: "API_KEY=xQ9fK2mP7zR4aL8nW1bV"}, true},
		{"github token", types.ScanRequest{Text: "token ghp_0123456789012345678901234567890123ab"}, true},
		{"secret file attached", types.ScanRequest{Text: "look at this", Paths: []string{"/repo/.env"}}, true},
		{"benign prompt", types.ScanRequest{Text: "please refactor the login handler"}, false},
		{"benign attachment", types.ScanRequest{Text: "review", Paths: []string{"/repo/main.go"}}, false},
		// noise reduction: placeholders / env refs must NOT trip the scanner
		{"placeholder your_api_key", types.ScanRequest{Text: "api_key=your_api_key_here"}, false},
		{"env reference", types.ScanRequest{Text: "API_KEY=process.env.OPENAI_API_KEY"}, false},
		{"template reference", types.ScanRequest{Text: "api_key: ${OPENAI_API_KEY}"}, false},
		{"xxxx placeholder", types.ScanRequest{Text: "secret=xxxxxxxxxxxxxxxxxxxx"}, false},
		{"short value", types.ScanRequest{Text: "token=abc123"}, false},
		{"prose after keyword", types.ScanRequest{Text: "the api key is stored in the vault somewhere"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Scan(c.req).Found; got != c.want {
				t.Errorf("Scan(%+v) found=%v, want %v", c.req, got, c.want)
			}
		})
	}
}

// IsSecretPath flags real secret-file references but NOT plain prose that merely
// mentions "credentials"/"secret"/"id_rsa" (it's matched against whole Bash
// command strings, so loose substrings would cause false denies).
func TestIsSecretPath(t *testing.T) {
	secret := []string{
		"/repo/.env",
		"cat ~/.aws/credentials",
		"cp ~/.ssh/id_rsa /tmp",
		"openssl rsa -in server.pem",
		"cat ./secrets/token",
		"tar czf out secrets/",
		"read creds from path/credentials",
	}
	benign := []string{
		`echo "update the credentials doc"`,
		"grep -r credentials ./src",
		`git commit -m "refactor credentials flow"`,
		"npm run test:credentials",
		`echo "my secrets are safe"`,
		"echo id_rsapassword",
		"./mysecrets/run.sh",
	}
	for _, s := range secret {
		if !IsSecretPath(s) {
			t.Errorf("expected secret: %q", s)
		}
	}
	for _, s := range benign {
		if IsSecretPath(s) {
			t.Errorf("false positive (should be benign): %q", s)
		}
	}
}

// A detection carries critical severity; a clean result carries none.
func TestScanSeverity(t *testing.T) {
	if got := Scan(types.ScanRequest{Text: "AKIAIOSFODNN7EXAMPLE"}); got.Severity != "critical" {
		t.Errorf("detected secret should be critical, got %q", got.Severity)
	}
	if got := Scan(types.ScanRequest{Text: "please refactor the login handler"}); got.Severity != "" {
		t.Errorf("clean prompt should have no severity, got %q", got.Severity)
	}
}
