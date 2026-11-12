package caddycertkeeper

import (
	"bytes"
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// plusSlashKey is 32 bytes whose base64 uses the two characters the base64
// alphabets disagree on, and ends in padding.
var plusSlashKey = string(bytes.Repeat([]byte{0xfb, 0xef, 0xff}, 11)[:32])

func b64(key string) string { return base64KeyPrefix + base64.StdEncoding.EncodeToString([]byte(key)) }

func TestParseKey(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte(plusSlashKey))
	if !strings.ContainsAny(std, "+") || !strings.Contains(std, "/") || !strings.HasSuffix(std, "=") {
		t.Fatalf("fixture does not exercise + / and padding: %s", std)
	}

	t.Run("accepted", func(t *testing.T) {
		for name, tt := range map[string]struct{ value, want string }{
			"32 bytes of text are the key":      {testKeyA, testKeyA},
			"base64":                            {"base64:" + std, plusSlashKey},
			"base64 without padding":            {"base64:" + strings.TrimRight(std, "="), plusSlashKey},
			"base64url":                         {"base64:" + base64.URLEncoding.EncodeToString([]byte(plusSlashKey)), plusSlashKey},
			"base64url without padding":         {"base64:" + base64.RawURLEncoding.EncodeToString([]byte(plusSlashKey)), plusSlashKey},
			"base64 of bytes no text can hold":  {b64(rawKey), rawKey},
			"base64 of a text key is that key":  {b64(testKeyB), testKeyB},
			"32 bytes of text starting base64:": {"base64:AAAAAAAAAAAAAAAAAAAAAAAAA", "base64:AAAAAAAAAAAAAAAAAAAAAAAAA"},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := parseKey(tt.value)
				if err != nil {
					t.Fatal(err)
				}
				if got != keyOf(tt.want) {
					t.Errorf("key = %x, want %x", got, tt.want)
				}
			})
		}
	})

	t.Run("refused", func(t *testing.T) {
		for name, tt := range map[string]struct{ value, wantErr string }{
			"empty":                       {"", "got 0"},
			"short text":                  {"tooshort", "must have exactly 32 bytes, got 8"},
			"base64 without the prefix":   {std, "must have exactly 32 bytes, got 44"},
			"hex":                         {strings.Repeat("0123456789abcdef", 4), "must have exactly 32 bytes, got 64"},
			"hex with a prefix":           {"hex:" + strings.Repeat("0123456789abcdef", 4), "must have exactly 32 bytes"},
			"prefix in capitals":          {"BASE64:" + std, "must have exactly 32 bytes"},
			"nothing after the prefix":    {"base64:", "base64 of exactly 32 bytes, got 0"},
			"base64 of 16 bytes":          {"base64:" + base64.StdEncoding.EncodeToString(make([]byte, 16)), "base64 of exactly 32 bytes, got 16"},
			"base64 of 33 bytes":          {"base64:" + base64.StdEncoding.EncodeToString(make([]byte, 33)), "base64 of exactly 32 bytes, got 33"},
			"not base64":                  {"base64:" + strings.Repeat("!", 44), "not valid base64"},
			"base64 of 32 zero bytes":     {"base64:" + base64.StdEncoding.EncodeToString(make([]byte, 32)), "all zero"},
			"32 zero bytes":               {string(make([]byte, 32)), "all zero"},
			"a space inside":              {"base64:" + std[:20] + " " + std[20:], "not valid base64"},
			"a line break inside":         {"base64:" + std[:20] + "\n" + std[20:], "not valid base64"},
			"a character cut off the end": {"base64:" + strings.TrimRight(std, "=")[:42], "not valid base64"},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := parseKey(tt.value)
				assertError(t, err, tt.wantErr, "parsing the key")
				if got != [keySize]byte{} {
					t.Errorf("a key came back with the error: %x", got)
				}
				// The error describes the value without repeating it.
				if err != nil && len(tt.value) >= 8 && strings.Contains(err.Error(), tt.value[len(tt.value)-8:]) {
					t.Errorf("error repeats the key: %v", err)
				}
			})
		}
	})
}

// A base64: key works wherever a key can be configured, next to keys
// written the old way.
func TestBase64KeysFromEverySource(t *testing.T) {
	want := func(t *testing.T, s *S3) {
		t.Helper()
		if err := provisionKeys(t, s); err != nil {
			t.Fatal(err)
		}
		if keys := boxKeys(t, s); !slices.Equal(keys, keysOf(plusSlashKey, testKeyA, rawKey)) {
			t.Errorf("keys = %x", keys)
		}
	}

	t.Run("config", func(t *testing.T) {
		want(t, &S3{Logger: zap.NewNop(), EncryptionKey: b64(plusSlashKey), OldEncryptionKeys: []string{testKeyA, b64(rawKey)}})
	})

	t.Run("Caddyfile, unquoted", func(t *testing.T) {
		s, err := parseBlock("encryption_key " + b64(plusSlashKey) + " " + testKeyA + " " + b64(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if s.EncryptionKey != b64(plusSlashKey) {
			t.Fatalf("the Caddyfile changed the key: %q", s.EncryptionKey)
		}
		s.Logger = zap.NewNop()
		want(t, s)
	})

	t.Run("files", func(t *testing.T) {
		want(t, &S3{Logger: zap.NewNop(), EncryptionKeyFile: []string{
			writeKeyFile(t, b64(plusSlashKey)+"\n"), writeKeyFile(t, testKeyA+"\r\n"), writeKeyFile(t, rawKey),
		}})
	})

	t.Run("SSM", func(t *testing.T) {
		fake := &fakeSSM{t: t, params: map[string]fakeSSMParam{
			"/caddy/key":       {"SecureString", b64(plusSlashKey)},
			"/caddy/key-old":   {"SecureString", testKeyA + "\n"},
			"/caddy/key-older": {"SecureString", b64(rawKey)},
		}}
		want(t, &S3{
			Logger: zap.NewNop(), ssmClient: fake.client(),
			EncryptionKeySSM: []string{"/caddy/key", "/caddy/key-old", "/caddy/key-older"},
		})
	})
}

func TestBadBase64KeysAreRejectedEverywhere(t *testing.T) {
	bad := "base64:" + base64.StdEncoding.EncodeToString([]byte("thirty-three bytes, one too many!"))
	fake := &fakeSSM{t: t, params: map[string]fakeSSMParam{"/caddy/key": {"SecureString", bad}}}

	for name, s := range map[string]*S3{
		"config":  {EncryptionKey: bad},
		"old key": {EncryptionKey: testKeyA, OldEncryptionKeys: []string{bad}},
		"file":    {EncryptionKeyFile: []string{writeKeyFile(t, bad+"\n")}},
		"SSM":     {EncryptionKeySSM: []string{"/caddy/key"}, ssmClient: fake.client()},
	} {
		t.Run(name, func(t *testing.T) {
			s.Logger = zap.NewNop()
			err := provisionKeys(t, s)
			assertError(t, err, "base64 of exactly 32 bytes, got 33", "setting up encryption")
			if s.iowrap != nil {
				t.Error("storage set up despite the bad key")
			}
			if err != nil && strings.Contains(err.Error(), bad[len(base64KeyPrefix):]) {
				t.Errorf("error repeats the key: %v", err)
			}
		})
	}

	if _, err := parseBlock("encryption_key " + bad); err == nil {
		t.Error("Caddyfile with a bad base64 key was accepted")
	}
}

// Moving from a 32-character key to a random one is an ordinary rotation:
// the new key first, the old one after it.
func TestRotatingFromATextKeyToARandomOne(t *testing.T) {
	f, srv := newFakeS3(t)
	ctx := context.Background()
	instance := encryptedInstances(t, f, srv)

	if err := instance(testKeyA).Store(ctx, "site.key", []byte("private key")); err != nil {
		t.Fatal(err)
	}
	if got, err := instance(b64(rawKey), testKeyA).Load(ctx, "site.key"); err != nil || string(got) != "private key" {
		t.Fatalf("rotated instance: %q, %v", got, err)
	}
	// Re-encrypted on that read, so the random key alone is enough now, and
	// the old one no longer opens it.
	if got, err := instance(b64(rawKey)).Load(ctx, "site.key"); err != nil || string(got) != "private key" {
		t.Fatalf("new key alone: %q, %v", got, err)
	}
	if _, err := instance(testKeyA).Load(ctx, "site.key"); err == nil {
		t.Error("the old key still opens the object")
	}

	// Writing the old text key as base64 changes nothing: it is the same key.
	if err := instance(testKeyB).Store(ctx, "other.key", []byte("data")); err != nil {
		t.Fatal(err)
	}
	if got, err := instance(b64(testKeyB)).Load(ctx, "other.key"); err != nil || string(got) != "data" {
		t.Fatalf("same key written as base64: %q, %v", got, err)
	}
}
