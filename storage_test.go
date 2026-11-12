package caddycertkeeper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// The keys of a small but realistic store: two issuers, three sites, ACME
// accounts, OCSP staples and ECH configs.
var storeKeys = []string{
	"acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.com/admin.json",
	"acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.com/admin.key",
	"acme/acme-v02.api.letsencrypt.org-directory/users/ops@example.com/ops.json",
	"acme/acme-v02.api.letsencrypt.org-directory/users/ops@example.com/ops.key",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.json",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.key",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.org/example.org.crt",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.org/example.org.json",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.org/example.org.key",
	"certificates/acme.zerossl.com-v2-dv90/example.net/example.net.crt",
	"certificates/acme.zerossl.com-v2-dv90/example.net/example.net.json",
	"certificates/acme.zerossl.com-v2-dv90/example.net/example.net.key",
	"ech/configs/10/config.bin",
	"ech/configs/10/key.bin",
	"ech/configs/10/meta.json",
	"ech/configs/107/config.bin",
	"ech/configs/107/key.bin",
	"ech/configs/107/meta.json",
	"last_clean.json",
	"ocsp/example.com-1a2b3c4d",
	"ocsp/example.org-5e6f7a8b",
}

// newStorePair returns an S3 storage on the fake and certmagic's own file
// storage, holding the same keys. The file storage is the reference: Caddy
// and certmagic are written against how it behaves.
func newStorePair(t *testing.T) (*S3, *certmagic.FileStorage, *fakeS3) {
	t.Helper()
	f, srv := newFakeS3(t)
	s := f.instance(srv)
	s.Prefix = "caddy/certs"
	if err := provisionKeys(t, s); err != nil {
		t.Fatal(err)
	}
	ref := &certmagic.FileStorage{Path: t.TempDir()}

	ctx := context.Background()
	for _, key := range storeKeys {
		for _, storage := range []certmagic.Storage{s, ref} {
			if err := storage.Store(ctx, key, []byte("value of "+key)); err != nil {
				t.Fatalf("Store %s: %v", key, err)
			}
		}
	}
	// An object outside the configured prefix, which the storage must never
	// list or delete.
	f.seed("caddy/certs-of-another-app/keep.me", time.Now())
	return s, ref, f
}

func sorted(keys []string) []string {
	out := append([]string{}, keys...)
	sort.Strings(out)
	return out
}

var listedPaths = []string{
	"",
	"acme",
	"acme/acme-v02.api.letsencrypt.org-directory/users",
	"acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.com",
	"certificates",
	"certificates/acme-v02.api.letsencrypt.org-directory",
	"certificates/acme-v02.api.letsencrypt.org-directory/example.com",
	"ech/configs",
	"ech/configs/10", // must not include ech/configs/107
	"ocsp",
}

func TestListNonRecursiveMatchesFileStorage(t *testing.T) {
	s, ref, f := newStorePair(t)
	ctx := context.Background()

	for _, pageSize := range []int{1000, 2} {
		f.pageSize = pageSize
		for _, p := range listedPaths {
			t.Run(fmt.Sprintf("page size %d/%q", pageSize, p), func(t *testing.T) {
				want, err := ref.List(ctx, p, false)
				if err != nil {
					t.Fatalf("file storage: %v", err)
				}
				got, err := s.List(ctx, p, false)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if fmt.Sprint(sorted(got)) != fmt.Sprint(sorted(want)) {
					t.Errorf("List(%q, false)\n got %q\nwant %q", p, sorted(got), sorted(want))
				}
			})
		}
	}
}

// Recursively, the file storage also returns the directories it walks
// through; only the terminal keys are compared.
func TestListRecursiveMatchesFileStorage(t *testing.T) {
	s, ref, f := newStorePair(t)
	ctx := context.Background()
	f.pageSize = 5

	for _, p := range listedPaths {
		t.Run(fmt.Sprintf("%q", p), func(t *testing.T) {
			all, err := ref.List(ctx, p, true)
			if err != nil {
				t.Fatalf("file storage: %v", err)
			}
			var want []string
			for _, key := range all {
				if info, statErr := ref.Stat(ctx, key); statErr == nil && info.IsTerminal {
					want = append(want, key)
				}
			}
			got, err := s.List(ctx, p, true)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if fmt.Sprint(sorted(got)) != fmt.Sprint(sorted(want)) {
				t.Errorf("List(%q, true)\n got %q\nwant %q", p, sorted(got), sorted(want))
			}
		})
	}
}

func TestStatAndExistsMatchFileStorage(t *testing.T) {
	s, ref, _ := newStorePair(t)
	ctx := context.Background()

	keys := []string{
		"last_clean.json", // a file
		"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt",
		"certificates", // directories
		"certificates/acme-v02.api.letsencrypt.org-directory/example.com",
		"acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.com",
		"ech/configs/10",
		"ech/configs/1", // a prefix of other keys' names, but not a directory
		"ech/configs/42",
		"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.pem",
		"nothing-here",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			if got, want := s.Exists(ctx, key), ref.Exists(ctx, key); got != want {
				t.Errorf("Exists = %v, file storage says %v", got, want)
			}

			want, wantErr := ref.Stat(ctx, key)
			got, err := s.Stat(ctx, key)
			if wantErr != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("Stat error = %v, want fs.ErrNotExist", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if got.Key != want.Key || got.IsTerminal != want.IsTerminal {
				t.Errorf("Stat = {Key: %q, IsTerminal: %v}, file storage says {Key: %q, IsTerminal: %v}",
					got.Key, got.IsTerminal, want.Key, want.IsTerminal)
			}
			if got.Modified.IsZero() || time.Since(got.Modified) > time.Minute {
				t.Errorf("Stat Modified = %v, want about now", got.Modified)
			}
		})
	}
}

func TestDeleteMatchesFileStorage(t *testing.T) {
	s, ref, f := newStorePair(t)
	f.pageSize = 2
	ctx := context.Background()

	for _, key := range []string{
		"ocsp/example.com-1a2b3c4d",                           // a file
		"ech/configs/10",                                      // a directory; ech/configs/107 must survive
		"certificates/acme-v02.api.letsencrypt.org-directory", // a directory of directories
		"ech/configs/42",                                      // not there: not an error
	} {
		for _, storage := range []certmagic.Storage{s, ref} {
			if err := storage.Delete(ctx, key); err != nil {
				t.Fatalf("Delete %s: %v", key, err)
			}
		}
	}

	var want []string
	all, err := ref.List(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range all {
		if info, statErr := ref.Stat(ctx, key); statErr == nil && info.IsTerminal {
			want = append(want, key)
		}
	}
	got, err := s.List(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sorted(got)) != fmt.Sprint(sorted(want)) {
		t.Errorf("keys left after the deletes\n got %q\nwant %q", sorted(got), sorted(want))
	}
	if len(got) != len(storeKeys)-1-3-6 {
		t.Errorf("%d keys left, want %d", len(got), len(storeKeys)-1-3-6)
	}
	if _, ok := f.get("caddy/certs-of-another-app/keep.me"); !ok {
		t.Error("an object outside the configured prefix was deleted")
	}
}

// Deleting the root of the storage must not empty it, whatever the caller
// meant: this plugin has emptied buckets before.
func TestDeleteOfTheRootDeletesNothing(t *testing.T) {
	s, _, f := newStorePair(t)
	ctx := context.Background()

	for _, key := range []string{"", "/", "//"} {
		if err := s.Delete(ctx, key); err != nil {
			t.Fatalf("Delete(%q): %v", key, err)
		}
	}
	got, err := s.List(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(storeKeys) {
		t.Errorf("%d keys left of %d", len(got), len(storeKeys))
	}
	if _, ok := f.get("caddy/certs-of-another-app/keep.me"); !ok {
		t.Error("an object outside the configured prefix was deleted")
	}
}

func certPEM(t *testing.T, name string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// certmagic's periodic storage clean walks issuers, sites and site assets
// with non-recursive listings, and removes the certificates that expired.
func TestCertmagicCleanStorageRemovesExpiredCerts(t *testing.T) {
	f, srv := newFakeS3(t)
	s := f.instance(srv)
	s.Prefix = "caddy"
	s.EncryptionKey = testKeyA
	if err := provisionKeys(t, s); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const issuer = "certificates/acme-v02.api.letsencrypt.org-directory/"
	store := func(site string, notAfter time.Time) {
		for ext, value := range map[string][]byte{
			".crt":  certPEM(t, site, notAfter),
			".key":  []byte("private key of " + site),
			".json": []byte(`{"sans":["` + site + `"]}`),
		} {
			if err := s.Store(ctx, issuer+site+"/"+site+ext, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	store("expired.example.com", time.Now().Add(-30*24*time.Hour))
	store("valid.example.com", time.Now().Add(30*24*time.Hour))

	err := certmagic.CleanStorage(ctx, s, certmagic.CleanStorageOptions{
		Logger:                 zap.NewNop(),
		OCSPStaples:            true,
		ExpiredCerts:           true,
		ExpiredCertGracePeriod: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CleanStorage: %v", err)
	}

	left, err := s.List(ctx, "certificates", true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		issuer + "valid.example.com/valid.example.com.crt",
		issuer + "valid.example.com/valid.example.com.json",
		issuer + "valid.example.com/valid.example.com.key",
	}
	if fmt.Sprint(sorted(left)) != fmt.Sprint(want) {
		t.Errorf("certificates left after the clean\n got %q\nwant %q", sorted(left), want)
	}
}
