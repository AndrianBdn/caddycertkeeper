package caddycertkeeper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/caddyserver/caddy/v2"
)

// The objects of an ACME account, which CertMagic reads only when it issues
// or renews a certificate.
const (
	accountKey  = "acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.com/admin.key"
	accountJSON = "acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.com/admin.json"
)

// storeAccountKey stores the ACME account's key under testKeyA, the old key
// of these tests.
func storeAccountKey(t *testing.T, instance func(key string, oldKeys ...string) *S3) {
	t.Helper()
	if err := instance(testKeyA).Store(context.Background(), accountKey, []byte("an ACME account key")); err != nil {
		t.Fatal(err)
	}
}

// runSweep runs the sweep of s and returns what it logged.
func runSweep(ctx context.Context, s *S3) *bytes.Buffer {
	logger, logs := bufferLogger()
	s.Logger = logger
	s.sweep(ctx)
	return logs
}

// assertSummary checks the line a sweep logs when it has finished.
func assertSummary(t *testing.T, logs *bytes.Buffer, level string, objects, rewritten, left, unreadable int) {
	t.Helper()
	var summary map[string]any
	lines := bufio.NewScanner(bytes.NewReader(logs.Bytes()))
	for lines.Scan() {
		var line map[string]any
		if err := json.Unmarshal(lines.Bytes(), &line); err != nil {
			t.Fatalf("log line is not JSON: %s", lines.Bytes())
		}
		if line["msg"] == "re-encryption sweep finished" {
			summary = line
		}
	}
	if summary == nil {
		t.Fatalf("the sweep logged no summary:\n%s", logs)
	}

	if summary["level"] != level {
		t.Errorf("summary logged at level %v, want %s", summary["level"], level)
	}
	for field, want := range map[string]int{
		"objects": objects, "rewritten": rewritten, "left_under_old_keys": left, "unreadable": unreadable,
	} {
		if got, _ := summary[field].(float64); int(got) != want {
			t.Errorf("summary: %s = %v, want %d", field, summary[field], want)
		}
	}
}

// The sweep brings every object under the current key, the ACME account
// included, and says so: that is the signal that the old key can go.
func TestSweepReencryptsEveryObject(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	oldOnly := instance(testKeyA)
	rotated := instance(testKeyB, testKeyA)
	newOnly := instance(testKeyB)
	for _, s := range []*S3{oldOnly, rotated, newOnly} {
		s.Prefix = "caddy-certs"
	}

	underOld := []string{accountKey, accountJSON, "certificates/ca/removed.example.com/removed.example.com.key"}
	for _, key := range underOld {
		if err := oldOnly.Store(ctx, key, []byte("value of "+key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := newOnly.Store(ctx, "certificates/ca/example.com/example.com.crt", []byte("already rotated")); err != nil {
		t.Fatal(err)
	}
	// A lock another instance holds, and something outside the storage's
	// prefix: neither is an object of the storage.
	f.seed(rotated.objLockName("issue_cert_example.com"), time.Now())
	f.seed("elsewhere/object", time.Now())

	current, _ := f.get("caddy-certs/certificates/ca/example.com/example.com.crt")
	elsewhere, _ := f.get("elsewhere/object")

	logs := runSweep(ctx, rotated)

	for _, key := range underOld {
		got, err := newOnly.Load(ctx, key)
		if err != nil || string(got) != "value of "+key {
			t.Errorf("%s after the sweep, read with the new key alone: %q, %v", key, got, err)
		}
	}
	if after, _ := f.get("caddy-certs/certificates/ca/example.com/example.com.crt"); after.etag != current.etag {
		t.Error("an object already under the current key was rewritten")
	}
	if after, _ := f.get("elsewhere/object"); after.etag != elsewhere.etag {
		t.Error("an object outside the prefix was rewritten")
	}

	// The lock is not counted, or reported as unreadable, and neither is
	// what lies outside the prefix.
	assertSummary(t, logs, "info", 4, 3, 0, 0)

	// A second sweep finds nothing left to do.
	assertSummary(t, runSweep(ctx, rotated), "info", 4, 0, 0, 0)
}

// An object no configured key opens is reported and left alone: the summary
// must not read as "everything is under the current key".
func TestSweepReportsWhatItCannotRead(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	if err := instance(testKeyC).Store(ctx, "under-a-forgotten-key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := instance(testKeyA).Store(ctx, "under-the-old-key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	before, _ := f.get("under-a-forgotten-key")

	logs := runSweep(ctx, instance(testKeyB, testKeyA))

	if after, _ := f.get("under-a-forgotten-key"); after.etag != before.etag {
		t.Error("an object that could not be read was rewritten")
	}
	assertSummary(t, logs, "warn", 2, 1, 0, 1)
	if !bytes.Contains(logs.Bytes(), []byte(`"key":"under-a-forgotten-key"`)) {
		t.Errorf("the unreadable object is not named in the log:\n%s", logs)
	}
}

// An instance that may read the bucket but not write to it cannot rewrite
// anything: every object under an old key is reported as left there.
func TestSweepReportsWhatItCouldNotRewrite(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	storeAccountKey(t, instance)
	f.denyPut = true

	logs := runSweep(context.Background(), instance(testKeyB, testKeyA))

	assertSummary(t, logs, "warn", 1, 0, 1, 0)
	if !bytes.Contains(logs.Bytes(), []byte(`"msg":"re-encryption sweep left an object under an old encryption key","key":"`+accountKey+`"`)) {
		t.Errorf("the object left under the old key is not named in the log:\n%s", logs)
	}
}

// An instance still on the first step of a rollout may store an object under
// the old key between the sweep's read and its rewrite. The sweep looks at
// that version too, rather than counting the object as done or as lost.
func TestSweepFollowsAConcurrentWrite(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	oldOnly := instance(testKeyA)
	if err := oldOnly.Store(ctx, "site.crt", []byte("the old certificate")); err != nil {
		t.Fatal(err)
	}
	renewedBody := oldOnly.iowrap.Seal([]byte("the renewed certificate"))
	f.afterGet = func(key string) {
		f.afterGet = nil
		f.write(key, renewedBody, time.Now())
	}

	logs := runSweep(ctx, instance(testKeyB, testKeyA))

	got, err := instance(testKeyB).Load(ctx, "site.crt")
	if err != nil || string(got) != "the renewed certificate" {
		t.Errorf("after the sweep, read with the new key alone: %q, %v", got, err)
	}
	assertSummary(t, logs, "info", 1, 1, 0, 0)
}

// An object that keeps changing under the sweep is counted as possibly
// still under an old key, not as done.
func TestSweepGivesUpOnAnObjectThatKeepsChanging(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	oldOnly := instance(testKeyA)
	if err := oldOnly.Store(ctx, "site.crt", []byte("version 0")); err != nil {
		t.Fatal(err)
	}
	f.afterGet = func(key string) {
		f.write(key, oldOnly.iowrap.Seal([]byte("another version")), time.Now())
	}

	assertSummary(t, runSweep(ctx, instance(testKeyB, testKeyA)), "warn", 1, 0, 1, 0)
}

// A sweep whose config is unloaded stops, and does not log a summary that
// could be taken for a finished one.
func TestSweepStopsWithItsContext(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	oldOnly := instance(testKeyA)
	for _, key := range []string{"a", "b", "c"} {
		if err := oldOnly.Store(context.Background(), key, []byte("value")); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.afterGet = func(string) { cancel() }

	logs := runSweep(ctx, instance(testKeyB, testKeyA))

	if bytes.Contains(logs.Bytes(), []byte("re-encryption sweep finished")) {
		t.Errorf("a cancelled sweep logged a summary:\n%s", logs)
	}
	if !bytes.Contains(logs.Bytes(), []byte("re-encryption sweep stopped before it finished")) {
		t.Errorf("a cancelled sweep did not say it stopped:\n%s", logs)
	}
}

// A config unloaded while the sweep is listing: that is a stopped sweep, not
// a storage that cannot be listed.
func TestSweepStoppedWhileListing(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	storeAccountKey(t, instance)

	ctx, cancel := context.WithCancel(context.Background())
	f.afterList = cancel

	logs := runSweep(ctx, instance(testKeyB, testKeyA))

	if !bytes.Contains(logs.Bytes(), []byte("re-encryption sweep stopped before it finished")) {
		t.Errorf("a sweep cancelled while listing did not say it stopped:\n%s", logs)
	}
	for _, msg := range []string{"re-encryption sweep finished", "re-encryption sweep failed"} {
		if bytes.Contains(logs.Bytes(), []byte(msg)) {
			t.Errorf("a sweep cancelled while listing logged %q:\n%s", msg, logs)
		}
	}
}

// An object removed after the listing, as an expired certificate is by a
// storage clean, is not there to be under any key.
func TestSweepSkipsAnObjectRemovedSinceTheListing(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	ctx := context.Background()

	oldOnly := instance(testKeyA)
	for _, key := range []string{"expired.crt", "site.crt"} {
		if err := oldOnly.Store(ctx, key, []byte("value")); err != nil {
			t.Fatal(err)
		}
	}
	f.afterList = func() { delete(f.objects, "expired.crt") }

	assertSummary(t, runSweep(ctx, instance(testKeyB, testKeyA)), "info", 1, 1, 0, 0)
}

// failedGets fails every GET of an object with an error that says a file
// does not exist, as the SDK's does when a credentials file has gone.
type failedGets struct{ next http.RoundTripper }

func (f failedGets) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet && !r.URL.Query().Has("list-type") {
		return nil, &fs.PathError{Op: "open", Path: "/run/secrets/token", Err: fs.ErrNotExist}
	}
	return f.next.RoundTrip(r)
}

// An object that could not be fetched is unreadable whatever the error says.
// Only the service saying there is no such object makes it a removed one.
func TestSweepDoesNotTakeAFailedReadForARemovedObject(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)
	storeAccountKey(t, instance)

	rotated := instance(testKeyB, testKeyA)
	rotated.Client = s3sdk.New(rotated.Client.Options(), func(o *s3sdk.Options) {
		o.HTTPClient = &http.Client{Transport: failedGets{http.DefaultTransport}}
		o.Retryer = aws.NopRetryer{}
	})

	assertSummary(t, runSweep(context.Background(), rotated), "warn", 1, 0, 0, 1)
}

// Without an ETag the rewrite cannot be made conditional, so it is not made.
func TestSweepReportsWhatHasNoETag(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	storeAccountKey(t, instance)
	before, _ := f.get(accountKey)
	f.noETag = true

	assertSummary(t, runSweep(context.Background(), instance(testKeyB, testKeyA)), "warn", 1, 0, 1, 0)
	if after, _ := f.get(accountKey); after.etag != before.etag {
		t.Error("an object was rewritten without a condition on the version that was read")
	}
}

// The storage cannot ask for a name that starts with a slash after the
// prefix. Such an object must not be passed over in silence: it may be
// under an old key.
func TestSweepReportsANameItCannotAddress(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	rotated := instance(testKeyB, testKeyA)
	rotated.Prefix = "caddy-certs"
	f.mu.Lock()
	f.write("caddy-certs//site.crt", instance(testKeyA).iowrap.Seal([]byte("value")), time.Now())
	f.mu.Unlock()

	logs := runSweep(context.Background(), rotated)

	assertSummary(t, logs, "warn", 1, 0, 0, 1)
	if !bytes.Contains(logs.Bytes(), []byte(`"key":"caddy-certs//site.crt"`)) {
		t.Errorf("the object is not named in the log:\n%s", logs)
	}
}

// A sweep that cannot list the storage knows nothing, and logs no summary.
func TestSweepThatCannotListLogsNoSummary(t *testing.T) {
	logs := runSweep(context.Background(), newUnreachableS3())

	if bytes.Contains(logs.Bytes(), []byte("re-encryption sweep finished")) {
		t.Errorf("a sweep that listed nothing logged a summary:\n%s", logs)
	}
	if !bytes.Contains(logs.Bytes(), []byte("re-encryption sweep failed: listing the storage")) {
		t.Errorf("the failed listing is not in the log:\n%s", logs)
	}
}

// A config that is unloaded before the sweep is due, as one that is only
// validated is, reads and writes nothing.
func TestSweepIsNotStartedForAnUnloadedConfig(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	storeAccountKey(t, instance)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rotated := instance(testKeyB, testKeyA)
	logger, logs := bufferLogger()
	rotated.Logger = logger
	rotated.sweepAfter(ctx, time.Hour)

	if logs.Len() > 0 {
		t.Errorf("a config that was unloaded before the sweep was due started it:\n%s", logs)
	}
}

// A sweep started by provisioning stops when the config is unloaded: it
// runs on the config's context.
func TestProvisionedSweepStopsWhenTheConfigIsUnloaded(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	oldOnly := instance(testKeyA)
	for _, key := range []string{"a", "b", "c"} {
		if err := oldOnly.Store(context.Background(), key, []byte("value")); err != nil {
			t.Fatal(err)
		}
	}

	// The first read waits until the config is unloaded.
	var reads atomic.Int32
	firstRead, unloaded := make(chan struct{}), make(chan struct{})
	f.afterGet = func(string) {
		if reads.Add(1) == 1 {
			close(firstRead)
			<-unloaded
		}
	}

	unload := provisionOnFake(t, srv, testKeyB, testKeyA)
	select {
	case <-firstRead:
	case <-time.After(10 * time.Second):
		close(unloaded)
		t.Fatal("the sweep did not start")
	}
	unload()
	close(unloaded)

	time.Sleep(100 * time.Millisecond)
	if n := reads.Load(); n != 1 {
		t.Errorf("the sweep read %d objects, want it to stop after the one it was reading", n)
	}
}

// provisionOnFake provisions a storage on the fake as Caddy does, with a
// sweep that is due at once. The config is unloaded when the test ends.
//
// The storage keeps the logger Caddy gave it: a sweep may be using it.
func provisionOnFake(t *testing.T, srv *httptest.Server, key string, oldKeys ...string) (unload context.CancelFunc) {
	t.Helper()
	isolateAWSEnv(t)
	old := sweepDelay
	sweepDelay = 0
	t.Cleanup(func() { sweepDelay = old })

	s := &S3{
		Bucket: "test", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "id", SecretKey: "secret",
		EncryptionKey: key, OldEncryptionKeys: oldKeys,
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := s.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	return cancel
}

// Provisioning a storage that has old keys starts the sweep: the ACME
// account is rewritten without anything loading it.
func TestProvisionWithOldKeysSweeps(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	storeAccountKey(t, instance)
	provisionOnFake(t, srv, testKeyB, testKeyA)

	newOnly := instance(testKeyB)
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := newOnly.Load(context.Background(), accountKey)
		if err == nil && string(got) == "an ACME account key" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ACME account was not re-encrypted after provisioning: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A storage with one key has nothing to rotate, and reads nothing by itself.
func TestProvisionWithoutOldKeysDoesNotSweep(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	storeAccountKey(t, instance)
	var reads atomic.Int32
	f.afterGet = func(string) { reads.Add(1) }

	provisionOnFake(t, srv, testKeyA)

	time.Sleep(100 * time.Millisecond)
	if n := reads.Load(); n != 0 {
		t.Errorf("a storage without old keys read %d objects after provisioning", n)
	}
}

// An object no configured key opens is an error, not a missing object.
// CertMagic registers a new ACME account when the configured one is missing;
// it must not do that because an old key was removed too early.
func TestLoadOfAnUndecryptableObjectIsNotNotExist(t *testing.T) {
	f, srv := newFakeS3(t)
	instance := encryptedInstances(t, f, srv)

	storeAccountKey(t, instance)
	_, err := instance(testKeyB).Load(context.Background(), accountKey)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load = %v, want an error that is not fs.ErrNotExist", err)
	}
}
