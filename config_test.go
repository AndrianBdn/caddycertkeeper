package caddycertkeeper

import (
	"bytes"
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func parseCaddyfile(input string) (*S3, error) {
	s := new(S3)
	return s, s.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
}

func TestCaddyfileOptions(t *testing.T) {
	s, err := parseCaddyfile(`s3 {
		bucket "my-certificates"
		region eu-central-1
		prefix caddy-certs
		access_key ` + testAccessKey + `
		secret_key ` + testSecretKey + `
		profile work
		role_arn arn:aws:iam::123456789012:role/caddy
		insecure true
		use_path_style true
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Bucket != "my-certificates" || s.Region != "eu-central-1" || s.Prefix != "caddy-certs" ||
		s.AccessKey != testAccessKey || s.SecretKey != testSecretKey || s.Profile != "work" ||
		s.RoleARN != "arn:aws:iam::123456789012:role/caddy" || !s.Insecure || !s.UsePathStyle {
		t.Errorf("parsed options do not match the Caddyfile: %+v", []any{
			s.Bucket, s.Region, s.Prefix, s.Profile, s.RoleARN, s.Insecure, s.UsePathStyle,
		})
	}
}

func TestCaddyfileDefaults(t *testing.T) {
	t.Run("region and prefix", func(t *testing.T) {
		s, err := parseCaddyfile("s3 {\n\tbucket b\n}")
		if err != nil {
			t.Fatal(err)
		}
		if s.Region != "us-east-1" || s.Prefix != "acme" || s.Endpoint != "" || s.UsePathStyle || s.Insecure {
			t.Errorf("region=%q prefix=%q endpoint=%q path_style=%v insecure=%v", s.Region, s.Prefix, s.Endpoint, s.UsePathStyle, s.Insecure)
		}
	})

	t.Run("a custom endpoint means path style", func(t *testing.T) {
		s, err := parseCaddyfile("s3 {\n\tbucket b\n\tendpoint https://minio.example.com\n\tuse_path_style false\n}")
		if err != nil {
			t.Fatal(err)
		}
		if !s.UsePathStyle {
			t.Error("use_path_style is off for a custom endpoint")
		}
	})

	t.Run("host becomes the endpoint", func(t *testing.T) {
		s, err := parseCaddyfile("s3 {\n\tbucket b\n\thost minio.example.com\n}")
		if err != nil {
			t.Fatal(err)
		}
		if s.Endpoint != "https://minio.example.com" || !s.UsePathStyle {
			t.Errorf("endpoint=%q path_style=%v", s.Endpoint, s.UsePathStyle)
		}
	})

	t.Run("an empty encryption key means none", func(t *testing.T) {
		s, err := parseCaddyfile("s3 {\n\tbucket b\n\tencryption_key \"\"\n}")
		if err != nil {
			t.Fatal(err)
		}
		if s.EncryptionKey != "" {
			t.Errorf("encryption_key = %q", s.EncryptionKey)
		}
	})
}

// What used to be skipped without a word is refused: an option that is not
// applied is worse than a config that does not load.
func TestCaddyfileMistakesAreRejected(t *testing.T) {
	block := func(lines string) string { return "s3 {\n\tbucket b\n" + lines + "\n}" }
	for name, input := range map[string]string{
		"insecure without a value":       block("\tinsecure"),
		"use_path_style without a value": block("\tuse_path_style"),
		"region without a value":         block("\tregion"),
		"bucket without a value":         "s3 {\n\tbucket\n}",
		"two values for one option":      block("\tregion us-east-1 eu-west-1"),
		"two values for a flag":          block("\tinsecure true false"),
		"not a boolean":                  block("\tinsecure yes-please"),
		"unknown option":                 block("\tbukcet b"),
		"unknown option without a value": block("\tbukcet"),
		"argument before the block":      "s3 my-certificates {\n\tbucket b\n}",
		"encryption_key without a value": block("\tencryption_key"),
		"ssm without a parameter":        block("\tencryption_key_ssm"),
		"ssm with an empty parameter":    block("\tencryption_key_ssm \"\""),
		"ssm with an empty old one":      block("\tencryption_key_ssm /caddy/key \"\""),
		"no bucket":                      "s3 {\n\tregion us-east-1\n}",
		"no block":                       "s3",
		"host and endpoint":              block("\thost a.example.com\n\tendpoint https://b.example.com"),
	} {
		t.Run(name, func(t *testing.T) {
			s, err := parseCaddyfile(input)
			if err == nil {
				t.Fatalf("want an error, got %#v", s)
			}
		})
	}
}

// isolateAWSEnv keeps the developer's or the CI's AWS settings out of what
// the SDK resolves.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	none := filepath.Join(t.TempDir(), "none")
	t.Setenv("AWS_CONFIG_FILE", none)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", none)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"} {
		t.Setenv(name, "")
	}
}

// provision runs the module's Provision as Caddy does after loading it from
// JSON, which is the only thing a JSON config goes through.
func provision(t *testing.T, s *S3) error {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	err := s.Provision(ctx)
	s.Logger = zap.NewNop()
	return err
}

func TestProvisionRequiresABucket(t *testing.T) {
	isolateAWSEnv(t)
	s := &S3{Region: "us-east-1"}
	err := provision(t, s)
	assertError(t, err, "bucket is required", "provisioning without a bucket")
	if s.Client != nil {
		t.Error("client built despite the missing bucket")
	}
}

func TestProvisionAppliesHost(t *testing.T) {
	isolateAWSEnv(t)

	t.Run("host alone", func(t *testing.T) {
		s := &S3{Bucket: "b", Region: "us-east-1", Host: "minio.example.com"}
		if err := provision(t, s); err != nil {
			t.Fatal(err)
		}
		if got := aws.ToString(s.Client.Options().BaseEndpoint); got != "https://minio.example.com" {
			t.Errorf("client endpoint = %q, want the host", got)
		}
	})

	// What a Caddyfile with 'host' is adapted to.
	t.Run("host with the endpoint derived from it", func(t *testing.T) {
		s := &S3{Bucket: "b", Region: "us-east-1", Host: "minio.example.com", Endpoint: "https://minio.example.com", UsePathStyle: true}
		if err := provision(t, s); err != nil {
			t.Fatal(err)
		}
		if got := aws.ToString(s.Client.Options().BaseEndpoint); got != "https://minio.example.com" {
			t.Errorf("client endpoint = %q", got)
		}
	})

	t.Run("endpoint wins over host", func(t *testing.T) {
		s := &S3{Bucket: "b", Region: "us-east-1", Host: "old.example.com", Endpoint: "http://new.example.com:9000"}
		if err := provision(t, s); err != nil {
			t.Fatal(err)
		}
		if got := aws.ToString(s.Client.Options().BaseEndpoint); got != "http://new.example.com:9000" {
			t.Errorf("client endpoint = %q", got)
		}
	})
}

// A JSON config that works today keeps putting its objects where they are
// and addressing the bucket the way it does.
func TestProvisionLeavesPrefixAndPathStyleAlone(t *testing.T) {
	isolateAWSEnv(t)
	s := &S3{Bucket: "b", Region: "us-east-1", Endpoint: "https://s3.example.com"}
	if err := provision(t, s); err != nil {
		t.Fatal(err)
	}
	if s.Prefix != "" || s.objName("certificates/a.crt") != "certificates/a.crt" {
		t.Errorf("prefix = %q, want none", s.Prefix)
	}
	if s.Client.Options().UsePathStyle {
		t.Error("path style switched on for a JSON config that did not ask for it")
	}
}

func TestProvisionRegion(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		env        string
		want       string
	}{
		{"configured", "eu-central-1", "", "eu-central-1"},
		{"configured wins over the environment", "eu-central-1", "ap-southeast-2", "eu-central-1"},
		{"from the environment", "", "ap-southeast-2", "ap-southeast-2"},
		{"nothing anywhere", "", "", "us-east-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateAWSEnv(t)
			t.Setenv("AWS_REGION", tt.env)

			s := &S3{Bucket: "b", Region: tt.configured}
			if err := provision(t, s); err != nil {
				t.Fatal(err)
			}
			if got := s.Client.Options().Region; got != tt.want {
				t.Errorf("client region = %q, want %q", got, tt.want)
			}

			// The region in use is the one that is logged.
			var buf bytes.Buffer
			logger := zap.New(zapcore.NewCore(
				zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buf), zapcore.DebugLevel))
			logger.Info("storage", zap.Any("storage", s))
			if !strings.Contains(buf.String(), `"region":"`+tt.want+`"`) {
				t.Errorf("logged storage does not name region %q: %s", tt.want, buf.String())
			}
		})
	}
}

// A config as it comes out of JSON, provisioned and used against the fake.
func TestProvisionedStorageWorks(t *testing.T) {
	isolateAWSEnv(t)
	f, srv := newFakeS3(t)

	s := &S3{
		Bucket: "test", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "id", SecretKey: "secret", EncryptionKey: testKeyA,
	}
	if err := provision(t, s); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := s.Store(ctx, "certificates/a.crt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.get("certificates/a.crt"); !ok {
		t.Error("object is not at the bucket root, where a JSON config without a prefix puts it")
	}
	got, err := s.Load(ctx, "certificates/a.crt")
	if err != nil || string(got) != "hello" {
		t.Errorf("Load = %q, %v", got, err)
	}
}

func TestInsecureReachesAnEndpointWithAnUntrustedCertificate(t *testing.T) {
	isolateAWSEnv(t)
	f := &fakeS3{t: t, objects: make(map[string]*fakeObject), pageSize: 1000}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)

	instance := func(insecure bool) *S3 {
		s := &S3{Bucket: "test", Endpoint: srv.URL, UsePathStyle: true, AccessKey: "id", SecretKey: "secret", Insecure: insecure}
		if err := provision(t, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctx := context.Background()

	if err := instance(true).Store(ctx, "a.crt", []byte("hello")); err != nil {
		t.Fatalf("insecure: %v", err)
	}
	if _, ok := f.get("a.crt"); !ok {
		t.Error("insecure: nothing stored")
	}

	err := instance(false).Store(ctx, "b.crt", []byte("hello"))
	assertError(t, err, "certificate", "storing without 'insecure'")
	if _, ok := f.get("b.crt"); ok {
		t.Error("stored over an unverified connection without 'insecure'")
	}
}

// 'insecure' turns verification off and leaves the rest of the SDK's HTTP
// client as it is.
func TestInsecureKeepsTheRestOfTheTransport(t *testing.T) {
	insecure := insecureHTTPClient().GetTransport()
	standard := awshttp.NewBuildableClient().GetTransport()

	if insecure.TLSClientConfig == nil || !insecure.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("certificate verification is still on")
	}
	if standard.TLSClientConfig != nil && standard.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the SDK's own client lost verification too")
	}
	if insecure.Proxy == nil {
		t.Error("proxy settings from the environment are not used")
	}
	if insecure.IdleConnTimeout <= 0 || insecure.IdleConnTimeout != standard.IdleConnTimeout {
		t.Errorf("idle connection timeout = %v, the SDK's is %v", insecure.IdleConnTimeout, standard.IdleConnTimeout)
	}
	if insecure.TLSHandshakeTimeout != standard.TLSHandshakeTimeout || insecure.MaxIdleConns != standard.MaxIdleConns {
		t.Error("timeouts or connection limits differ from the SDK's")
	}
}

// The encryption keys come from AWS whatever the bucket's endpoint is, and
// 'insecure' must not reach that connection.
func TestInsecureDoesNotApplyToSSM(t *testing.T) {
	isolateAWSEnv(t)
	s := &S3{Logger: zap.NewNop(), Bucket: "b", Region: "us-east-1", Insecure: true, AccessKey: "id", SecretKey: "secret"}
	cfg, err := s.loadAWSConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	skipsVerify := func(client any) bool {
		t.Helper()
		bc, ok := client.(*awshttp.BuildableClient)
		if !ok {
			t.Fatalf("HTTP client is a %T", client)
		}
		tls := bc.GetTransport().TLSClientConfig
		return tls != nil && tls.InsecureSkipVerify
	}
	if !skipsVerify(s.newS3Client(cfg).Options().HTTPClient) {
		t.Error("'insecure' did not reach the S3 client")
	}
	if skipsVerify(s.newSSMClient(cfg).Options().HTTPClient) {
		t.Error("'insecure' reached the SSM client")
	}
}
