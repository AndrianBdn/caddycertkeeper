package caddycertkeeper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"go.uber.org/zap"
)

type fakeSSMParam struct {
	typ   string
	value string
}

// fakeSSM answers GetParameter the way Parameter Store does, and refuses to
// hand out a SecureString that was not asked for decrypted.
type fakeSSM struct {
	t      *testing.T
	params map[string]fakeSSMParam

	mu      sync.Mutex
	regions []string // signing region of each request, in order
}

// client returns a real SSM client talking to the fake.
func (f *fakeSSM) client() *ssm.Client {
	srv := httptest.NewServer(f)
	f.t.Cleanup(srv.Close)
	return ssm.New(ssm.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("id", "secret", ""),
	})
}

func (f *fakeSSM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if target := r.Header.Get("X-Amz-Target"); target != "AmazonSSM.GetParameter" {
		f.t.Errorf("fake ssm: unexpected operation %q", target)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Credential=id/20261111/<region>/ssm/aws4_request
	if parts := strings.Split(r.Header.Get("Authorization"), "/"); len(parts) > 2 {
		f.mu.Lock()
		f.regions = append(f.regions, parts[2])
		f.mu.Unlock()
	}

	var in struct {
		Name           string
		WithDecryption bool
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &in); err != nil {
		f.t.Errorf("fake ssm: bad request body: %v", err)
	}

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	p, ok := f.params[in.Name]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"__type":"ParameterNotFound","message":"no such parameter"}`)
		return
	}
	value := p.value
	if p.typ == "SecureString" && !in.WithDecryption {
		value = "AQICAHh-ciphertext-not-the-key"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"Parameter": map[string]any{"Name": in.Name, "Type": p.typ, "Value": value, "Version": 1},
	})
}

func TestEncryptionKeysFromSSM(t *testing.T) {
	const arnParam = "arn:aws:ssm:eu-west-1:123456789012:parameter/caddy/key-old"
	fake := &fakeSSM{t: t, params: map[string]fakeSSMParam{
		"/caddy/key":   {"SecureString", testKeyB + "\n"}, // stored with a trailing newline
		arnParam:       {"SecureString", testKeyA},
		"/caddy/plain": {"String", testKeyC},
		"/caddy/short": {"SecureString", "not-32-bytes"},
	}}
	client := fake.client()

	keysFor := func(params ...string) ([]string, error) {
		s := &S3{Logger: zap.NewNop(), EncryptionKeySSM: params, ssmClient: client}
		return s.encryptionKeys(context.Background(), aws.Config{})
	}

	t.Run("keys come back in the order the parameters are listed", func(t *testing.T) {
		keys, err := keysFor("/caddy/key", arnParam, "/caddy/plain")
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(keys) != fmt.Sprint([]string{testKeyB, testKeyA, testKeyC}) {
			t.Errorf("keys = %q", keys)
		}
	})

	t.Run("a parameter given by ARN is read from the ARN's region", func(t *testing.T) {
		fake.mu.Lock()
		fake.regions = nil
		fake.mu.Unlock()
		if _, err := keysFor("/caddy/key", arnParam); err != nil {
			t.Fatal(err)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fmt.Sprint(fake.regions) != fmt.Sprint([]string{"us-east-1", "eu-west-1"}) {
			t.Errorf("request regions = %v", fake.regions)
		}
	})

	t.Run("missing parameter", func(t *testing.T) {
		_, err := keysFor("/caddy/key", "/caddy/absent")
		assertError(t, err, `SSM parameter "/caddy/absent"`, "reading keys")
	})

	t.Run("wrong key size", func(t *testing.T) {
		_, err := keysFor("/caddy/short")
		assertError(t, err, `SSM parameter "/caddy/short" must have exactly 32 bytes, got 12`, "reading keys")
		if err != nil && strings.Contains(err.Error(), "not-32-bytes") {
			t.Errorf("error repeats the parameter's value: %v", err)
		}
	})
}

// A storage keyed from SSM reads what a storage with the same keys written
// in its config stored, and the other way round; the key stays out of the
// config.
func TestSSMKeysEncryptLikeInlineKeys(t *testing.T) {
	f, srv := newFakeS3(t)
	ctx := context.Background()
	fake := &fakeSSM{t: t, params: map[string]fakeSSMParam{
		"/caddy/key-new": {"SecureString", testKeyB},
		"/caddy/key-old": {"SecureString", testKeyA},
	}}

	fromSSM := f.instance(srv)
	fromSSM.EncryptionKeySSM = []string{"/caddy/key-new", "/caddy/key-old"}
	fromSSM.ssmClient = fake.client()
	if err := provisionKeys(t, fromSSM); err != nil {
		t.Fatal(err)
	}

	oldInline := f.instance(srv)
	oldInline.EncryptionKey = testKeyA
	newInline := f.instance(srv)
	newInline.EncryptionKey = testKeyB
	for _, s := range []*S3{oldInline, newInline} {
		if err := provisionKeys(t, s); err != nil {
			t.Fatal(err)
		}
	}

	if err := oldInline.Store(ctx, "before", []byte("under the old key")); err != nil {
		t.Fatal(err)
	}
	if got, err := fromSSM.Load(ctx, "before"); err != nil || string(got) != "under the old key" {
		t.Fatalf("reading with the old key from SSM: %q, %v", got, err)
	}

	if err := fromSSM.Store(ctx, "after", []byte("under the new key")); err != nil {
		t.Fatal(err)
	}
	if got, err := newInline.Load(ctx, "after"); err != nil || string(got) != "under the new key" {
		t.Fatalf("reading what the SSM-keyed storage wrote: %q, %v", got, err)
	}

	config, err := json.Marshal(fromSSM)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "JSON config of an SSM-keyed storage", string(config))
}
