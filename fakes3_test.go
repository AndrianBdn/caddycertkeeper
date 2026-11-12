package caddycertkeeper

import (
	"crypto/md5" // #nosec G501 -- S3 computes ETags this way; nothing here is security
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

// fakeS3 is an in-memory, path-style S3 endpoint for one bucket. It applies
// each request atomically, honours If-None-Match: * and If-Match on PUT the
// way S3 and S3-compatible services with conditional writes do, and lists
// objects (ListObjectsV2) with prefix, delimiter and pagination.
type fakeS3 struct {
	t *testing.T

	mu      sync.Mutex
	objects map[string]*fakeObject

	// pageSize caps the keys and common prefixes in one listing page.
	pageSize int

	// afterGet runs after a GET of an object is answered and before any
	// other request is served, with mu held: what it does to the bucket is
	// what another instance did between a reader's GET and its next request.
	afterGet func(key string)

	// ignoreDeleteIfMatch deletes regardless of If-Match, as services that
	// do not support conditional deletes do.
	ignoreDeleteIfMatch bool
}

type fakeObject struct {
	body     []byte
	etag     string
	modified time.Time
}

func newFakeS3(t *testing.T) (*fakeS3, *httptest.Server) {
	t.Helper()
	f := &fakeS3{t: t, objects: make(map[string]*fakeObject), pageSize: 1000}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// instance returns a new S3 storage talking to the fake, as a separate
// process would.
func (f *fakeS3) instance(srv *httptest.Server) *S3 {
	client := s3sdk.New(s3sdk.Options{
		BaseEndpoint:               aws.String(srv.URL),
		Region:                     "us-east-1",
		UsePathStyle:               true,
		Credentials:                credentials.NewStaticCredentialsProvider("id", "secret", ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &S3{Logger: zap.NewNop(), Client: client, Bucket: "test"}
}

// seed stores an object last written at modified.
func (f *fakeS3) seed(key string, modified time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.write(key, []byte(modified.UTC().Format(time.RFC3339)), modified)
}

func (f *fakeS3) get(key string) (fakeObject, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[key]
	if !ok {
		return fakeObject{}, false
	}
	return *obj, true
}

// write stores an object. Its ETag is the MD5 of its content, as S3 and
// S3-compatible services compute it for single-part uploads.
func (f *fakeS3) write(key string, body []byte, modified time.Time) string {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%x", md5.Sum(body))) // #nosec G401 -- as above
	f.objects[key] = &fakeObject{body: body, etag: etag, modified: modified}
	return etag
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/test/")

	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
		f.list(w, r)
		return
	}
	obj, exists := f.objects[key]

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			f.t.Errorf("fake s3: reading body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("If-None-Match") == "*" && exists {
			writeError(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		if m := r.Header.Get("If-Match"); m != "" && (!exists || obj.etag != m) {
			if !exists {
				writeError(w, http.StatusNotFound, "NoSuchKey")
				return
			}
			writeError(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		w.Header().Set("ETag", f.write(key, body, time.Now()))
		w.WriteHeader(http.StatusOK)

	case http.MethodGet, http.MethodHead:
		if !exists {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", obj.etag)
		w.Header().Set("Last-Modified", obj.modified.UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", fmt.Sprint(len(obj.body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(obj.body)
			if f.afterGet != nil {
				f.afterGet(key)
			}
		}

	case http.MethodDelete:
		if m := r.Header.Get("If-Match"); m != "" && !f.ignoreDeleteIfMatch && exists && obj.etag != m {
			writeError(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// list answers ListObjectsV2. Keys and common prefixes are returned in one
// sorted sequence, pageSize entries at a time, as S3 does.
func (f *fakeS3) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefix, delimiter, after := q.Get("prefix"), q.Get("delimiter"), q.Get("continuation-token")

	type entry struct {
		name     string
		isPrefix bool
	}
	var entries []entry
	seen := map[string]bool{}
	for key := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" {
			if i := strings.Index(key[len(prefix):], delimiter); i >= 0 {
				common := key[:len(prefix)+i+len(delimiter)]
				if !seen[common] {
					seen[common] = true
					entries = append(entries, entry{common, true})
				}
				continue
			}
		}
		entries = append(entries, entry{key, false})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	type content struct {
		Key          string
		LastModified string
		ETag         string
		Size         int
	}
	type commonPrefix struct {
		Prefix string
	}
	result := struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		Name                  string
		Prefix                string
		Delimiter             string `xml:",omitempty"`
		KeyCount              int
		IsTruncated           bool
		NextContinuationToken string `xml:",omitempty"`
		Contents              []content
		CommonPrefixes        []commonPrefix
	}{Name: "test", Prefix: prefix, Delimiter: delimiter}

	pageSize := f.pageSize
	if n, err := strconv.Atoi(q.Get("max-keys")); err == nil && n < pageSize {
		pageSize = n
	}
	for _, e := range entries {
		if after != "" && e.name <= after {
			continue
		}
		if result.KeyCount == pageSize {
			result.IsTruncated = true
			break
		}
		result.KeyCount++
		result.NextContinuationToken = e.name
		if e.isPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix{e.name})
			continue
		}
		obj := f.objects[e.name]
		result.Contents = append(result.Contents, content{e.name, obj.modified.UTC().Format(time.RFC3339Nano), obj.etag, len(obj.body)})
	}
	if !result.IsTruncated {
		result.NextContinuationToken = ""
	}

	w.Header().Set("Content-Type", "application/xml")
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		f.t.Errorf("fake s3: encoding listing: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}
