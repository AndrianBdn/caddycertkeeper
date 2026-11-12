package caddycertkeeper

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"go.uber.org/zap"
)

// rawKey is a key no config file could hold: it is not valid UTF-8, has a
// NUL in it and ends in a newline.
var rawKey = string([]byte{
	0xff, 0xfe, 0x00, 0x01, 0x80, 0x81, 0xc0, 0xc1, 0xf5, 0xf6, 0x0d, 0x0a, 0x20, 0x09, 0x7f, 0x90,
	0xa0, 0xb0, 0xd0, 0xe0, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x0a,
})

// crKey is a key of raw bytes whose last byte is a carriage return.
var crKey = rawKey[:keySize-1] + "\r"

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The bytes of a configured key are the key. Nothing decodes it, so a key
// that looks like hex is 32 ASCII characters, not 16 bytes, and nothing
// stretches it either.
func TestEncryptionKeyIsUsedAsItsLiteralBytes(t *testing.T) {
	const hexLooking = "0123456789abcdef0123456789abcdef"

	s := &S3{Logger: zap.NewNop(), EncryptionKey: hexLooking}
	if err := provisionKeys(t, s); err != nil {
		t.Fatal(err)
	}
	if keys := boxKeys(t, s); keys[0] != keyOf(hexLooking) {
		t.Errorf("secretbox key = %x, want the ASCII bytes of the configured key", keys[0])
	}

	// 32 bytes as 64 hex digits or as base64 are not accepted in place of
	// the 32 bytes themselves.
	for name, key := range map[string]string{
		"64 hex digits": strings.Repeat("0123456789abcdef", 4),
		"base64":        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		t.Run(name, func(t *testing.T) {
			bad := &S3{Logger: zap.NewNop(), EncryptionKey: key}
			assertError(t, provisionKeys(t, bad), "exactly 32 bytes", "setting up encryption")
		})
	}

	// The size is counted in bytes, not characters.
	multibyte := strings.Repeat("é", 16)
	if err := provisionKeys(t, &S3{Logger: zap.NewNop(), EncryptionKey: multibyte}); err != nil {
		t.Errorf("16 two-byte characters refused: %v", err)
	}
}

func TestEncryptionKeysFromFiles(t *testing.T) {
	t.Run("what the file may hold", func(t *testing.T) {
		tests := []struct {
			name    string
			content string
			want    string
		}{
			{"exactly the key", testKeyA, testKeyA},
			{"the key and a newline", testKeyA + "\n", testKeyA},
			{"the key and a CRLF", testKeyA + "\r\n", testKeyA},
			{"raw bytes ending in a newline", rawKey, rawKey},
			{"raw bytes and a newline", rawKey + "\n", rawKey},
			{"raw bytes ending in a carriage return, and a newline", crKey + "\n", crKey},
			{"raw bytes ending in a carriage return, and a CRLF", crKey + "\r\n", crKey},
			{"a base64: key and a newline", b64(rawKey) + "\n", rawKey},
			{"a base64: key and a CRLF", b64(rawKey) + "\r\n", rawKey},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s := &S3{Logger: zap.NewNop(), EncryptionKeyFile: []string{writeKeyFile(t, tt.content)}}
				keys, err := s.encryptionKeys(context.Background(), aws.Config{})
				if err != nil {
					t.Fatal(err)
				}
				if len(keys) != 1 || keys[0] != keyOf(tt.want) {
					t.Errorf("key = %x, want %x", keys, tt.want)
				}
			})
		}
	})

	t.Run("first file encrypts, the others are old keys", func(t *testing.T) {
		s := &S3{Logger: zap.NewNop(), EncryptionKeyFile: []string{
			writeKeyFile(t, rawKey), writeKeyFile(t, testKeyA+"\n"), writeKeyFile(t, testKeyB),
		}}
		if err := provisionKeys(t, s); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(boxKeys(t, s), keysOf(rawKey, testKeyA, testKeyB)) {
			t.Error("keys are not in the order of the files")
		}
	})

	t.Run("bad files", func(t *testing.T) {
		good := writeKeyFile(t, testKeyA)
		tests := []struct {
			name    string
			files   []string
			wantErr string
		}{
			{"missing file", []string{filepath.Join(t.TempDir(), "nope")}, "nope"},
			{"missing old file", []string{good, filepath.Join(t.TempDir(), "nope")}, "nope"},
			{"empty name", []string{""}, "encryption_key_file: name 1 is empty"},
			{"empty file", []string{writeKeyFile(t, "")}, "exactly 32 bytes, got 0"},
			{"too short", []string{writeKeyFile(t, "short-key-in-a-file\n")}, "exactly 32 bytes, got 19"},
			{"too long", []string{writeKeyFile(t, testKeyA+testKeyB)}, "exactly 32 bytes, got 64"},
			{"two line endings", []string{writeKeyFile(t, testKeyA+"\n\n")}, "exactly 32 bytes, got 33"},
			{"hex of a key", []string{writeKeyFile(t, strings.Repeat("0123456789abcdef", 4)+"\n")}, "exactly 32 bytes, got 64"},
			{"a directory", []string{t.TempDir()}, "reading encryption key file"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s := &S3{Logger: zap.NewNop(), EncryptionKeyFile: tt.files}
				err := provisionKeys(t, s)
				assertError(t, err, tt.wantErr, "setting up encryption")
				if s.iowrap != nil {
					t.Error("storage set up despite the bad key file")
				}
				if err != nil {
					assertNoSecrets(t, "error", err.Error())
					if strings.Contains(err.Error(), "short-key") {
						t.Errorf("error repeats the content of the file: %v", err)
					}
				}
			})
		}
	})

	t.Run("one source of keys at a time", func(t *testing.T) {
		file := writeKeyFile(t, testKeyA)
		for name, s := range map[string]*S3{
			"file and key":      {EncryptionKey: testKeyB, EncryptionKeyFile: []string{file}},
			"file and ssm":      {EncryptionKeyFile: []string{file}, EncryptionKeySSM: []string{"/caddy/key"}},
			"file and old keys": {OldEncryptionKeys: []string{testKeyB}, EncryptionKeyFile: []string{file}},
			"all three":         {EncryptionKey: testKeyB, EncryptionKeyFile: []string{file}, EncryptionKeySSM: []string{"/caddy/key"}},
		} {
			t.Run(name, func(t *testing.T) {
				s.Logger = zap.NewNop()
				err := provisionKeys(t, s)
				if err == nil {
					t.Fatal("want an error")
				}
				assertNoSecrets(t, "error", err.Error())
			})
		}
	})
}

// A storage keyed from files reads what a storage with the same keys in its
// config stored, and the other way round; the keys stay out of the config
// and out of the log.
func TestFileKeysEncryptLikeInlineKeys(t *testing.T) {
	f, srv := newFakeS3(t)
	ctx := context.Background()

	fromFiles := f.instance(srv)
	fromFiles.EncryptionKeyFile = []string{writeKeyFile(t, testKeyB+"\n"), writeKeyFile(t, testKeyA)}
	logger, logged := bufferLogger()
	fromFiles.Logger = logger
	if err := provisionKeys(t, fromFiles); err != nil {
		t.Fatal(err)
	}

	instance := encryptedInstances(t, f, srv)
	oldInline, newInline := instance(testKeyA), instance(testKeyB)

	if err := oldInline.Store(ctx, "before", []byte("under the old key")); err != nil {
		t.Fatal(err)
	}
	if got, err := fromFiles.Load(ctx, "before"); err != nil || string(got) != "under the old key" {
		t.Fatalf("reading with the old key from a file: %q, %v", got, err)
	}
	// Read under the old key, so it was stored again under the current one.
	if got, err := newInline.Load(ctx, "before"); err != nil || string(got) != "under the old key" {
		t.Fatalf("reading what the file-keyed storage re-encrypted: %q, %v", got, err)
	}

	if err := fromFiles.Store(ctx, "after", []byte("under the new key")); err != nil {
		t.Fatal(err)
	}
	if got, err := newInline.Load(ctx, "after"); err != nil || string(got) != "under the new key" {
		t.Fatalf("reading what the file-keyed storage wrote: %q, %v", got, err)
	}

	config, err := json.Marshal(fromFiles)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "JSON config of a file-keyed storage", string(config))

	fromFiles.Logger.Info("storage", zap.Any("storage", fromFiles))
	assertNoSecrets(t, "log of a file-keyed storage", logged.String())
	for _, want := range []string{`"key_source":"encryption_key_file"`, `"old_encryption_keys":1`, `"encrypted":true`} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("log lacks %s: %s", want, logged.String())
		}
	}
}

// A key of raw bytes, which only a file can hold, works end to end.
func TestRawKeyFromAFile(t *testing.T) {
	f, srv := newFakeS3(t)
	ctx := context.Background()

	path := writeKeyFile(t, rawKey)
	a, b := f.instance(srv), f.instance(srv)
	for _, s := range []*S3{a, b} {
		s.EncryptionKeyFile = []string{path}
		if err := provisionKeys(t, s); err != nil {
			t.Fatal(err)
		}
	}

	if err := a.Store(ctx, "site.key", []byte("private key")); err != nil {
		t.Fatal(err)
	}
	stored, _ := f.get("site.key")
	if bytes.Contains(stored.body, []byte("private key")) {
		t.Error("object is stored in clear text")
	}
	if got, err := b.Load(ctx, "site.key"); err != nil || string(got) != "private key" {
		t.Fatalf("Load = %q, %v", got, err)
	}
}

func TestCaddyfileEncryptionKeyFile(t *testing.T) {
	s, err := parseBlock(`encryption_key_file /etc/caddy/cert.key "/etc/caddy/old cert.key"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/caddy/cert.key", "/etc/caddy/old cert.key"}
	if !slices.Equal(s.EncryptionKeyFile, want) || s.EncryptionKey != "" || len(s.EncryptionKeySSM) != 0 {
		t.Errorf("files = %q, key = %q, ssm = %v", s.EncryptionKeyFile, s.EncryptionKey, s.EncryptionKeySSM)
	}

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back S3
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.EncryptionKeyFile, want) {
		t.Errorf("encryption_key_file lost in the JSON round trip: %s", raw)
	}

	for name, lines := range map[string]string{
		"no file":        "encryption_key_file",
		"empty name":     `encryption_key_file ""`,
		"empty old name": `encryption_key_file /etc/caddy/cert.key ""`,
		"file and key":   "encryption_key " + testKeyA + "\nencryption_key_file /etc/caddy/cert.key",
		"file and ssm":   "encryption_key_ssm /caddy/key\nencryption_key_file /etc/caddy/cert.key",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBlock(lines); err == nil {
				t.Fatal("want an error")
			} else {
				assertNoSecrets(t, "error", err.Error())
			}
		})
	}
}
