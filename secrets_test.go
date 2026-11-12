package caddycertkeeper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

const (
	testAccessKey = "AKIATESTACCESSKEY000"
	testSecretKey = "test-secret-access-key-do-not-log"
	testKeyA      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testKeyB      = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	testKeyC      = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func storageWithSecrets() *S3 {
	return &S3{
		Logger:            zap.NewNop(),
		Endpoint:          "https://s3.example.com",
		Bucket:            "my-certificates",
		Region:            "eu-central-1",
		Prefix:            "caddy-certs",
		AccessKey:         testAccessKey,
		SecretKey:         testSecretKey,
		EncryptionKey:     testKeyA,
		OldEncryptionKeys: []string{testKeyB, testKeyC},
	}
}

func assertNoSecrets(t *testing.T, what, out string) {
	t.Helper()
	for _, secret := range []string{testAccessKey, testSecretKey, testKeyA, testKeyB, testKeyC} {
		if strings.Contains(out, secret) {
			t.Errorf("%s contains the secret %q: %s", what, secret, out)
		}
	}
}

// certmagic logs its storage with zap.Any("storage", storage) on every
// storage clean. That line must not carry credentials or encryption keys.
func TestLoggingTheStorageOmitsSecrets(t *testing.T) {
	logger, buf := bufferLogger()

	// As certmagic holds it: behind the certmagic.Storage interface.
	var storage certmagic.Storage = storageWithSecrets()
	logger.With(zap.Any("storage", storage)).Info("cleaning storage unit")

	out := buf.String()
	assertNoSecrets(t, "log line", out)

	var line struct {
		Storage map[string]any `json:"storage"`
	}
	if err := json.Unmarshal([]byte(out), &line); err != nil {
		t.Fatalf("log line is not JSON: %v: %s", err, out)
	}
	want := map[string]any{
		"module":             "caddy.storage.s3",
		"endpoint":           "https://s3.example.com",
		"bucket":             "my-certificates",
		"region":             "eu-central-1",
		"prefix":             "caddy-certs",
		"static_credentials": true,
		"encrypted":          true,
	}
	if !maps.Equal(line.Storage, want) {
		t.Errorf("logged storage = %v, want %v", line.Storage, want)
	}
}

func TestFormattingTheStorageOmitsSecrets(t *testing.T) {
	s := storageWithSecrets()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, s)
		assertNoSecrets(t, verb, out)
		if !strings.Contains(out, "my-certificates") {
			t.Errorf("%s = %q, want it to name the bucket", verb, out)
		}
	}
}

// The config must still round-trip through JSON with its secrets: Caddy
// adapts a Caddyfile to JSON and loads the module back from that.
func TestJSONConfigKeepsSecrets(t *testing.T) {
	raw, err := json.Marshal(storageWithSecrets())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back S3
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.AccessKey != testAccessKey || back.SecretKey != testSecretKey || back.EncryptionKey != testKeyA {
		t.Errorf("secrets lost in the JSON round trip: %s", raw)
	}
	if !slices.Equal(back.OldEncryptionKeys, []string{testKeyB, testKeyC}) {
		t.Errorf("old_encryption_keys = %v", back.OldEncryptionKeys)
	}
}

// provisionKeys does the part of Provision that sets up encryption.
func provisionKeys(t *testing.T, s *S3) error {
	t.Helper()
	keys, err := s.encryptionKeys(context.Background(), aws.Config{})
	if err != nil {
		return err
	}
	s.setupEncryption(keys)
	return nil
}

// encryptedInstances returns a function making storages on the fake with
// the given key and old keys.
func encryptedInstances(t *testing.T, f *fakeS3, srv *httptest.Server) func(key string, oldKeys ...string) *S3 {
	t.Helper()
	return func(key string, oldKeys ...string) *S3 {
		s := f.instance(srv)
		s.EncryptionKey, s.OldEncryptionKeys = key, oldKeys
		if err := provisionKeys(t, s); err != nil {
			t.Fatalf("setting up encryption: %v", err)
		}
		return s
	}
}

// Rotating the key: an instance given the new key, with the old one listed
// after it, reads what was written under the old key and writes under the
// new one.
func TestKeyRotation(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	oldOnly := instance(testKeyA)
	rotated := instance(testKeyB, testKeyA)
	newOnly := instance(testKeyB)

	// Written before the rotation.
	if err := oldOnly.Store(ctx, "before", []byte("written under the old key")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := newOnly.Load(ctx, "before"); err == nil {
		t.Fatal("an instance without the old key read an object written under it")
	}
	got, err := rotated.Load(ctx, "before")
	if err != nil {
		t.Fatalf("rotated instance reading an object written under the old key: %v", err)
	}
	if string(got) != "written under the old key" {
		t.Fatalf("got %q", got)
	}

	// Written after the rotation: under the new key, not the old one.
	if err = rotated.Store(ctx, "after", []byte("written under the new key")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err = newOnly.Load(ctx, "after")
	if err != nil {
		t.Fatalf("new-key instance reading what the rotated instance wrote: %v", err)
	}
	if string(got) != "written under the new key" {
		t.Fatalf("got %q", got)
	}
	if _, err := oldOnly.Load(ctx, "after"); err == nil {
		t.Fatal("the rotated instance encrypted with an old key")
	}

	// Nothing is stored in the clear.
	obj, _ := f.get("after")
	if bytes.Contains(obj.body, []byte("written under the new key")) {
		t.Fatal("object stored in clear text")
	}
}

// Loading an object that is still under an old key stores it again under
// the current one, so that the old key can eventually be dropped.
func TestLoadReencryptsUnderTheCurrentKey(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	oldOnly := instance(testKeyA)
	rotated := instance(testKeyB, testKeyA)
	newOnly := instance(testKeyB)

	if err := oldOnly.Store(ctx, "account.key", []byte("an ACME account key")); err != nil {
		t.Fatal(err)
	}
	before, _ := f.get("account.key")

	got, err := rotated.Load(ctx, "account.key")
	if err != nil || string(got) != "an ACME account key" {
		t.Fatalf("Load: %q, %v", got, err)
	}

	after, _ := f.get("account.key")
	if after.etag == before.etag {
		t.Fatal("object was not rewritten")
	}
	if bytes.Contains(after.body, []byte("an ACME account key")) {
		t.Fatal("object rewritten in clear text")
	}
	got, err = newOnly.Load(ctx, "account.key")
	if err != nil || string(got) != "an ACME account key" {
		t.Fatalf("an instance with only the new key reading the rewritten object: %q, %v", got, err)
	}
	if _, err := oldOnly.Load(ctx, "account.key"); err == nil {
		t.Fatal("the object is still readable with the old key alone")
	}

	// It is under the current key now: loading it again leaves it alone.
	if _, err := rotated.Load(ctx, "account.key"); err != nil {
		t.Fatal(err)
	}
	if again, _ := f.get("account.key"); again.etag != after.etag {
		t.Fatal("an object already under the current key was rewritten")
	}
}

// Another instance may store a new version of the object between this
// instance's read and its rewrite. The rewrite must not put the old version
// back.
func TestLoadDoesNotReencryptOverAConcurrentWrite(t *testing.T) {
	for _, change := range []string{"replaced", "deleted"} {
		t.Run("object "+change+" after it was read", func(t *testing.T) {
			f, srv := newFakeS3(t)
			instance := encryptedInstances(t, f, srv)
			ctx := context.Background()

			oldOnly := instance(testKeyA)
			rotated := instance(testKeyB, testKeyA)
			newOnly := instance(testKeyB)

			if err := oldOnly.Store(ctx, "site.crt", []byte("the old certificate")); err != nil {
				t.Fatal(err)
			}

			// What the other instance stores, sealed as it would seal it.
			renewedBody := newOnly.iowrap.Seal([]byte("the renewed certificate"))
			f.afterGet = func(key string) {
				f.afterGet = nil
				if change == "deleted" {
					delete(f.objects, key)
					return
				}
				f.write(key, renewedBody, time.Now())
			}

			// This instance read the old version before the change.
			got, err := rotated.Load(ctx, "site.crt")
			if err != nil || string(got) != "the old certificate" {
				t.Fatalf("Load: %q, %v", got, err)
			}

			obj, ok := f.get("site.crt")
			if change == "deleted" {
				if ok {
					t.Fatal("the rewrite brought back an object another instance deleted")
				}
				return
			}
			if !ok || !bytes.Equal(obj.body, renewedBody) {
				t.Fatal("the rewrite replaced the version another instance stored")
			}
			got, err = newOnly.Load(ctx, "site.crt")
			if err != nil || string(got) != "the renewed certificate" {
				t.Fatalf("reading the other instance's version: %q, %v", got, err)
			}
		})
	}
}

// A storage without old keys, or without encryption, never rewrites on load.
func TestLoadWithoutOldKeysDoesNotWrite(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	for name, s := range map[string]*S3{"encrypted": instance(testKeyA), "clear text": instance("")} {
		if err := s.Store(ctx, name, []byte("value")); err != nil {
			t.Fatal(err)
		}
		before, _ := f.get(name)
		if got, err := s.Load(ctx, name); err != nil || string(got) != "value" {
			t.Fatalf("%s: Load: %q, %v", name, got, err)
		}
		if after, _ := f.get(name); after.etag != before.etag || !after.modified.Equal(before.modified) {
			t.Errorf("%s: Load wrote to the object", name)
		}
	}
}

// A line with the wrong number of values is refused without repeating any
// of them: they may be a secret, or the halves of one that needed quoting.
func TestCaddyfileErrorsDoNotRepeatValues(t *testing.T) {
	for name, lines := range map[string]string{
		"extra value after the secret key":  "secret_key " + testSecretKey + " extra-value",
		"secret key split in two":           "secret_key first-half-of-it second-half-of-it",
		"extra value after the access key":  "access_key " + testAccessKey + " extra-value",
		"extra value after another option":  "region first-half-of-it second-half-of-it",
		"extra value after a flag":          "insecure first-half-of-it second-half-of-it",
		"encryption key that is too long":   "encryption_key " + testKeyA + "first-half-of-it",
		"old encryption key that is short":  "encryption_key " + testKeyA + " second-half-of-it",
		"encryption key file, then nothing": "encryption_key_file",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseBlock(lines)
			if err == nil {
				t.Fatal("want an error")
			}
			assertNoSecrets(t, "error", err.Error())
			for _, value := range []string{"extra-value", "first-half-of-it", "second-half-of-it"} {
				if strings.Contains(err.Error(), value) {
					t.Errorf("error repeats a value from the line: %v", err)
				}
			}
		})
	}
}

func TestBadKeyConfigIsRejected(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		oldKeys []string
		ssm     []string
		wantErr string
	}{
		{"short key", "short", nil, nil, "exactly 32 bytes"},
		{"short old key", testKeyA, []string{testKeyB, "short-old-key"}, nil, "old encryption key 2 must have exactly 32 bytes"},
		{"old keys without a key", "", []string{testKeyB}, nil, "encryption_key is empty"},
		{"key and ssm", testKeyA, nil, []string{"/caddy/key"}, "use one of them"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &S3{Logger: zap.NewNop(), EncryptionKey: tt.key, OldEncryptionKeys: tt.oldKeys, EncryptionKeySSM: tt.ssm}
			err := provisionKeys(t, s)
			assertError(t, err, tt.wantErr, "setting up encryption")
			if s.iowrap != nil {
				t.Error("storage set up despite the bad key config")
			}
			if err != nil {
				assertNoSecrets(t, "error", err.Error())
				if strings.Contains(err.Error(), "short") {
					t.Errorf("error repeats the key: %v", err)
				}
			}
		})
	}
}

func TestCaddyfileEncryptionKeys(t *testing.T) {
	t.Run("single key", func(t *testing.T) {
		s, err := parseBlock("\tencryption_key " + testKeyA)
		if err != nil {
			t.Fatal(err)
		}
		if s.EncryptionKey != testKeyA || len(s.OldEncryptionKeys) != 0 {
			t.Errorf("key = %q, old = %v", s.EncryptionKey, s.OldEncryptionKeys)
		}
	})

	t.Run("key followed by old keys", func(t *testing.T) {
		s, err := parseBlock("\tencryption_key " + testKeyA + " " + testKeyB + " \"" + testKeyC + "\"")
		if err != nil {
			t.Fatal(err)
		}
		if s.EncryptionKey != testKeyA || !slices.Equal(s.OldEncryptionKeys, []string{testKeyB, testKeyC}) {
			t.Errorf("key = %q, old = %v", s.EncryptionKey, s.OldEncryptionKeys)
		}
	})

	t.Run("no key", func(t *testing.T) {
		s, err := parseBlock("")
		if err != nil {
			t.Fatal(err)
		}
		if s.EncryptionKey != "" || len(s.OldEncryptionKeys) != 0 {
			t.Errorf("key = %q, old = %v", s.EncryptionKey, s.OldEncryptionKeys)
		}
	})

	t.Run("keys in SSM", func(t *testing.T) {
		s, err := parseBlock("\tencryption_key_ssm /caddy/key-new arn:aws:ssm:eu-west-1:123456789012:parameter/caddy/key")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"/caddy/key-new", "arn:aws:ssm:eu-west-1:123456789012:parameter/caddy/key"}
		if s.EncryptionKey != "" || !slices.Equal(s.EncryptionKeySSM, want) {
			t.Errorf("key = %q, ssm = %v", s.EncryptionKey, s.EncryptionKeySSM)
		}
	})

	for name, body := range map[string]string{
		"key and ssm":            "\tencryption_key " + testKeyA + "\n\tencryption_key_ssm /caddy/key",
		"short key":              "\tencryption_key tooshort",
		"short old key":          "\tencryption_key " + testKeyA + " tooshort",
		"old keys, empty key":    "\tencryption_key \"\" " + testKeyB,
		"second key is too long": "\tencryption_key " + testKeyA + " " + testKeyB + "B",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseBlock(body)
			if err == nil {
				t.Fatal("want an error")
			}
			assertNoSecrets(t, "error", err.Error())
		})
	}
}
