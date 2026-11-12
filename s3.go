package caddycertkeeper

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var ErrInvalidKey = errors.New("invalid key")

const (
	moduleID = "caddy.storage.s3"

	// defaultRegion is used when no region is configured anywhere.
	defaultRegion = "us-east-1"
)

type S3 struct {
	Logger *zap.Logger

	// S3
	Client       *s3sdk.Client
	Host         string `json:"host"`
	Endpoint     string `json:"endpoint"`
	Insecure     bool   `json:"insecure"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	Profile      string `json:"profile"`
	RoleARN      string `json:"role_arn"`
	Prefix       string `json:"prefix"`
	UsePathStyle bool   `json:"use_path_style,omitempty"`

	// EncryptionKey is optional. If you do not wish to encrypt your certificates and keys inside the S3 bucket, leave it empty.
	// It encrypts everything written and is tried first when reading. It is written either as "base64:"
	// followed by the base64 of the 32 bytes of the key, or as exactly 32 bytes of text, which are then the
	// key as they are. The key is used directly: nothing stretches a weak one.
	EncryptionKey string `json:"encryption_key"`

	// OldEncryptionKeys are former values of EncryptionKey. They are never used to encrypt; when EncryptionKey
	// does not decrypt an object, each of them is tried in order. This makes changing EncryptionKey a rolling
	// change: instances that have the new key keep reading what was written under the old ones.
	OldEncryptionKeys []string `json:"old_encryption_keys,omitempty"`

	// EncryptionKeySSM reads the encryption keys from AWS Systems Manager Parameter Store instead of the
	// config: each entry is the name or ARN of a parameter (a SecureString, ideally) whose value is one
	// key, written as in EncryptionKey. The first parameter's key encrypts; the others are old keys, tried in order when reading.
	// The parameters are read once, when the storage is provisioned, with the region and credentials the
	// S3 client uses. It cannot be combined with EncryptionKey.
	EncryptionKeySSM []string `json:"encryption_key_ssm,omitempty"`

	// EncryptionKeyFile reads the encryption keys from files instead of the config: each entry is the path
	// of a file holding one key: its 32 raw bytes, or the key as written in EncryptionKey. The first
	// file's key encrypts; the others are old keys, tried in order when reading. The files are read once,
	// when the storage is provisioned. It cannot be combined with EncryptionKey or EncryptionKeySSM.
	EncryptionKeyFile []string `json:"encryption_key_file,omitempty"`

	iowrap IO

	// ssmClient replaces the SSM client built from the AWS config; tests set it.
	ssmClient *ssm.Client

	locksMu sync.Mutex
	locks   map[string]*heldLock
}

func init() {
	caddy.RegisterModule(new(S3))
}

func (s3 *S3) Provision(ctx caddy.Context) error {
	s3.Logger = ctx.Logger(s3)

	if err := s3.checkConfig(); err != nil {
		return err
	}
	if s3.Host != "" {
		s3.Logger.Info("Using deprecated 'host' option, consider switching to 'endpoint'",
			zap.String("host", s3.Host),
			zap.String("endpoint", s3.Endpoint),
		)
	}

	cfg, err := s3.loadAWSConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}
	s3.Client = s3.newS3Client(cfg)

	keys, err := s3.encryptionKeys(ctx, cfg)
	if err != nil {
		return err
	}
	s3.setupEncryption(keys)
	return nil
}

// checkConfig applies the rules that hold for every config, whether it was
// written as a Caddyfile or as JSON. The Caddyfile's defaults are not among
// them: a JSON config gets no "acme" prefix and no path-style addressing
// unless it asks for them, as in certmagic-s3.
func (s3 *S3) checkConfig() error {
	if s3.Bucket == "" {
		return errors.New("bucket is required")
	}
	if s3.Host != "" && s3.Endpoint == "" {
		s3.Endpoint = "https://" + s3.Host
	}
	if _, err := s3.keySource(); err != nil {
		return err
	}
	_, err := s3.inlineKeys()
	return err
}

// loadAWSConfig resolves the region and credentials. The S3 client and, when
// the encryption keys are kept there, the SSM client are both built from it.
func (s3 *S3) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	configOptions := []func(*config.LoadOptions) error{
		config.WithRegion(s3.Region),
	}

	if s3.Endpoint != "" {
		// some non-AWS providers do not implement automatic checksums
		// see https://github.com/aws/aws-sdk-go-v2/discussions/2960 for more details
		configOptions = append(configOptions, config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired))
	}

	if s3.Insecure {
		s3.Logger.Warn("TLS certificate verification is disabled - this is insecure and should only be used for testing")
		// As in certmagic-s3, 'insecure' also covers the calls that fetch
		// credentials, such as the STS call for role_arn. Not with the keys
		// in SSM: then it stays on the bucket connection alone, so that the
		// credentials that can read the keys never cross an unverified one.
		if len(s3.EncryptionKeySSM) == 0 {
			configOptions = append(configOptions, config.WithHTTPClient(insecureHTTPClient()))
		}
	}

	if s3.AccessKey != "" && s3.SecretKey != "" {
		configOptions = append(configOptions, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s3.AccessKey, s3.SecretKey, "")))
	} else if s3.Profile != "" {
		configOptions = append(configOptions, config.WithSharedConfigProfile(s3.Profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, configOptions...)
	if err != nil {
		return aws.Config{}, err
	}

	// A JSON config may leave the region to the environment or the shared
	// config; when nothing names one, use the same default as the Caddyfile.
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	s3.Region = cfg.Region

	if s3.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, s3.RoleARN)
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return cfg, nil
}

// insecureHTTPClient is the SDK's own HTTP client with certificate
// verification switched off and nothing else changed: it keeps the proxy
// settings from the environment and the timeouts, idle connections included.
func insecureHTTPClient() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- what the 'insecure' option asks for
	})
}

func (s3 *S3) newS3Client(cfg aws.Config) *s3sdk.Client {
	var s3Options []func(*s3sdk.Options)

	if s3.Endpoint != "" {
		s3Options = append(s3Options, func(o *s3sdk.Options) {
			o.BaseEndpoint = aws.String(s3.Endpoint)
		})
	}

	if s3.UsePathStyle {
		s3Options = append(s3Options, func(o *s3sdk.Options) {
			o.UsePathStyle = true
		})
	}

	if s3.Insecure {
		s3Options = append(s3Options, func(o *s3sdk.Options) {
			o.HTTPClient = insecureHTTPClient()
		})
	}

	return s3sdk.NewFromConfig(cfg, s3Options...)
}

// MarshalLogObject is what a logger writes for this storage. certmagic logs
// its storage whole (zap.Any("storage", storage)) on every storage clean;
// without this method zap falls back to reflection and writes every field,
// credentials and encryption keys included.
func (s3 *S3) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("module", moduleID)
	enc.AddString("endpoint", s3.Endpoint)
	enc.AddString("bucket", s3.Bucket)
	enc.AddString("region", s3.Region)
	enc.AddString("prefix", s3.Prefix)
	if s3.Profile != "" {
		enc.AddString("profile", s3.Profile)
	}
	if s3.RoleARN != "" {
		enc.AddString("role_arn", s3.RoleARN)
	}
	enc.AddBool("static_credentials", s3.AccessKey != "" && s3.SecretKey != "")
	keySource, _ := s3.keySource()
	enc.AddBool("encrypted", keySource != "")
	return nil
}

// String keeps credentials and encryption keys out of anything that formats
// the storage with %v, %+v or %s.
func (s3 *S3) String() string {
	return fmt.Sprintf("s3 storage (endpoint=%q bucket=%q prefix=%q)", s3.Endpoint, s3.Bucket, s3.Prefix)
}

// GoString does the same for %#v.
func (s3 *S3) GoString() string {
	return s3.String()
}

func (s3 *S3) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: moduleID,
		New: func() caddy.Module {
			return new(S3)
		},
	}
}

func (s3 *S3) Store(ctx context.Context, key string, value []byte) error {
	start := time.Now()
	objName := s3.objName(key)

	if len(value) == 0 {
		return fmt.Errorf("%w: cannot store empty value", ErrInvalidKey)
	}

	s3.Logger.Info("storing object",
		zap.String("key", objName),
		zap.Int("size", len(value)),
		zap.String("bucket", s3.Bucket),
	)

	defer func() {
		s3.Logger.Debug("store completed",
			zap.String("key", objName),
			zap.Duration("duration", time.Since(start)),
		)
	}()

	if err := s3.putObject(ctx, objName, value, nil); err != nil {
		return fmt.Errorf("failed to store key %s: %w", key, err)
	}
	return nil
}

// putObject stores value, sealed, as the object objName. With ifMatch, the
// write only happens if the object still has that ETag.
func (s3 *S3) putObject(ctx context.Context, objName string, value []byte, ifMatch *string) error {
	sealed := s3.iowrap.Seal(value)
	_, err := s3.Client.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket:        aws.String(s3.Bucket),
		Key:           aws.String(objName),
		Body:          bytes.NewReader(sealed),
		ContentLength: aws.Int64(int64(len(sealed))),
		IfMatch:       ifMatch,
	})
	return err
}

func (s3 *S3) Load(ctx context.Context, key string) ([]byte, error) {
	start := time.Now()
	objName := s3.objName(key)

	s3.Logger.Info("loading object",
		zap.String("key", objName),
		zap.String("bucket", s3.Bucket),
	)

	defer func() {
		s3.Logger.Debug("load completed",
			zap.String("key", objName),
			zap.Duration("duration", time.Since(start)),
		)
	}()

	input := &s3sdk.GetObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(objName),
	}

	result, err := s3.Client.GetObject(ctx, input)
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to load key %s: %w", key, err)
	}
	defer func() { _ = result.Body.Close() }()

	stored, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read/decrypt data for key %s: %w", key, err)
	}
	buf, underOldKey, err := s3.iowrap.Open(stored)
	if err != nil {
		return nil, fmt.Errorf("failed to read/decrypt data for key %s: %w", key, err)
	}
	if underOldKey {
		s3.reencrypt(ctx, objName, buf, aws.ToString(result.ETag))
	}
	return buf, nil
}

// reencrypt stores an object that was just read under an old encryption key
// again, under the current one, so that the old key is eventually needed for
// nothing. The write names the ETag that was read: if another instance has
// replaced or removed the object in the meantime, the service refuses the
// write and that instance's version stands. No lock is needed for that.
//
// It is best effort. The caller has its data either way, and an object that
// was not rewritten is tried again the next time it is loaded.
func (s3 *S3) reencrypt(ctx context.Context, objName string, plain []byte, etag string) {
	if etag == "" {
		// Without the ETag the write could not be made conditional, and an
		// unconditional one could undo another instance's write.
		s3.Logger.Debug("not re-encrypting object: storage returned no ETag for it", zap.String("key", objName))
		return
	}

	err := s3.putObject(ctx, objName, plain, aws.String(etag))
	switch {
	case err == nil:
		s3.Logger.Info("re-encrypted object under the current encryption key", zap.String("key", objName))
	case isPreconditionFailed(err) || isNotFound(err):
		s3.Logger.Debug("not re-encrypting object: it changed since it was read", zap.String("key", objName))
	default:
		s3.Logger.Warn("re-encrypting object under the current encryption key failed",
			zap.String("key", objName),
			zap.Error(err),
		)
	}
}

// Delete removes key and, as certmagic requires of a storage, every key
// under it: a key can be a "directory" of other keys, such as a site's
// folder of certificate assets or an ECH config's folder.
func (s3 *S3) Delete(ctx context.Context, key string) error {
	start := time.Now()
	objName := s3.objName(key)

	s3.Logger.Info("deleting object",
		zap.String("key", objName),
		zap.String("bucket", s3.Bucket),
	)

	defer func() {
		s3.Logger.Debug("delete completed",
			zap.String("key", objName),
			zap.Duration("duration", time.Since(start)),
		)
	}()

	// The root of the storage is not something to delete, whatever the key
	// was meant to be: everything in the bucket lies under it.
	if isRootKey(key) {
		return nil
	}

	if err := s3.deleteObject(ctx, objName); err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}

	// List everything under the key before deleting any of it.
	var under []string
	paginator := s3sdk.NewListObjectsV2Paginator(s3.Client, &s3sdk.ListObjectsV2Input{
		Bucket: aws.String(s3.Bucket),
		Prefix: aws.String(s3.objDirName(key)),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list keys under %s to delete them: %w", key, err)
		}
		for _, obj := range page.Contents {
			under = append(under, aws.ToString(obj.Key))
		}
	}
	for _, name := range under {
		if err := s3.deleteObject(ctx, name); err != nil {
			return fmt.Errorf("failed to delete key %s: %w", key, err)
		}
	}
	return nil
}

func (s3 *S3) deleteObject(ctx context.Context, objName string) error {
	_, err := s3.Client.DeleteObject(ctx, &s3sdk.DeleteObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(objName),
	})
	return err
}

// Exists reports whether key is an object or a "directory" of other keys.
func (s3 *S3) Exists(ctx context.Context, key string) bool {
	objName := s3.objName(key)

	s3.Logger.Debug("checking object existence",
		zap.String("key", objName),
		zap.String("bucket", s3.Bucket),
	)

	exists := false
	if _, err := s3.headObject(ctx, key); err == nil {
		exists = true
	} else if isNotFound(err) {
		_, exists, _ = s3.statDir(ctx, key, 1)
	}

	s3.Logger.Debug("existence check completed",
		zap.String("key", objName),
		zap.Bool("exists", exists),
	)

	return exists
}

// headObject looks up the object at key. The root of the storage is never
// an object, only a directory.
func (s3 *S3) headObject(ctx context.Context, key string) (*s3sdk.HeadObjectOutput, error) {
	if isRootKey(key) {
		return nil, &types.NotFound{}
	}
	return s3.Client.HeadObject(ctx, &s3sdk.HeadObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(s3.objName(key)),
	})
}

// statDir reports whether any key lies under key, which makes key a
// "directory", and when the newest of the first maxKeys of them was
// written.
func (s3 *S3) statDir(ctx context.Context, key string, maxKeys int32) (modified time.Time, exists bool, err error) {
	out, err := s3.Client.ListObjectsV2(ctx, &s3sdk.ListObjectsV2Input{
		Bucket:  aws.String(s3.Bucket),
		Prefix:  aws.String(s3.objDirName(key)),
		MaxKeys: aws.Int32(maxKeys),
	})
	if err != nil {
		return time.Time{}, false, err
	}
	for _, obj := range out.Contents {
		if t := aws.ToTime(obj.LastModified); t.After(modified) {
			modified = t
		}
	}
	return modified, len(out.Contents) > 0, nil
}

// List returns the keys under path: all of them when recursive, otherwise
// only the ones directly under it, where a "directory" of further keys is
// listed once, as a key itself. certmagic and Caddy walk the storage level
// by level with non-recursive listings.
func (s3 *S3) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	var keys []string

	root := s3.objDirName("")
	dir := s3.objDirName(path)
	input := &s3sdk.ListObjectsV2Input{
		Bucket: aws.String(s3.Bucket),
		Prefix: aws.String(dir),
	}
	if !recursive {
		input.Delimiter = aws.String("/")
	}

	paginator := s3sdk.NewListObjectsV2Paginator(s3.Client, input)
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, obj := range result.Contents {
			name := aws.ToString(obj.Key)
			if name == dir {
				// A placeholder object for the directory itself, as S3
				// consoles create for a "folder": not a key in it.
				continue
			}
			keys = append(keys, strings.TrimPrefix(name, root))
		}
		for _, sub := range result.CommonPrefixes {
			name := strings.TrimSuffix(aws.ToString(sub.Prefix), "/")
			keys = append(keys, strings.TrimPrefix(name, root))
		}
	}

	return keys, nil
}

// Stat describes key: an object is a terminal key, and a key that other
// keys lie under is a "directory".
func (s3 *S3) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	s3.Logger.Debug("stat", zap.String("key", s3.objName(key)))

	head, err := s3.headObject(ctx, key)
	if err == nil {
		return certmagic.KeyInfo{
			Key:        key,
			Size:       aws.ToInt64(head.ContentLength),
			Modified:   aws.ToTime(head.LastModified),
			IsTerminal: true,
		}, nil
	}
	if !isNotFound(err) {
		return certmagic.KeyInfo{}, err
	}

	// Modified is the newest write among the first page of keys under the
	// directory. certmagic uses it to pick the most recently used ACME
	// account, whose folder holds two keys.
	modified, exists, err := s3.statDir(ctx, key, 1000)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	if !exists {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	return certmagic.KeyInfo{Key: key, Modified: modified, IsTerminal: false}, nil
}

// isRootKey reports whether key names the root of the storage.
func isRootKey(key string) bool {
	return strings.Trim(key, "/") == ""
}

func (s3 *S3) objName(key string) string {
	prefix := strings.Trim(s3.Prefix, "/")
	key = strings.TrimLeft(key, "/")

	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

// objDirName returns what the names of all objects under key start with.
// For the root of the storage that is the configured prefix, or nothing.
func (s3 *S3) objDirName(key string) string {
	key = strings.Trim(key, "/")
	if key == "" {
		return s3.objName("")
	}
	return s3.objName(key) + "/"
}

func (s3 *S3) objLockName(key string) string {
	return s3.objName(key) + ".lock"
}

// CertMagicStorage converts s to a certmagic.Storage instance.
func (s3 *S3) CertMagicStorage() (certmagic.Storage, error) {
	return s3, nil
}

// UnmarshalCaddyfile reads the storage block:
//
//	s3 {
//	    <option> <value>
//	    ...
//	}
func (s3 *S3) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // the module name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		if err := s3.setCaddyfileOption(d, d.Val()); err != nil {
			return err
		}
	}
	return s3.finishCaddyfile(d)
}

// setCaddyfileOption reads the value, or values, of the option the
// dispenser is on.
func (s3 *S3) setCaddyfileOption(d *caddyfile.Dispenser, option string) error {
	switch option {
	case "insecure":
		return boolArg(d, option, &s3.Insecure)
	case "use_path_style":
		return boolArg(d, option, &s3.UsePathStyle)
	case keysInFiles:
		return listArg(d, &s3.EncryptionKeyFile)
	case keysInSSM:
		return listArg(d, &s3.EncryptionKeySSM)
	case keysInConfig:
		var keys []string
		if err := listArg(d, &keys); err != nil {
			return err
		}
		s3.EncryptionKey, s3.OldEncryptionKeys = keys[0], keys[1:]
		return nil
	}

	dst, ok := map[string]*string{
		"host":       &s3.Host,
		"endpoint":   &s3.Endpoint,
		"bucket":     &s3.Bucket,
		"region":     &s3.Region,
		"access_key": &s3.AccessKey,
		"secret_key": &s3.SecretKey,
		"profile":    &s3.Profile,
		"role_arn":   &s3.RoleARN,
		"prefix":     &s3.Prefix,
	}[option]
	if !ok {
		return d.Errf("unknown configuration option: %s", option)
	}
	if !d.AllArgs(dst) {
		return oneValueErr(d, option)
	}
	return nil
}

// oneValueErr is the error for an option that was given no value or more
// than one. It names the option only: the values may be a secret, or the
// two halves of one that needed quoting.
func oneValueErr(d *caddyfile.Dispenser, option string) error {
	return d.Errf("%s takes exactly one value", option)
}

// boolArg reads the value of a flag. A flag without a value is an error,
// not true: TLS verification must not be switched off by omission.
func boolArg(d *caddyfile.Dispenser, option string, dst *bool) error {
	var value string
	if !d.AllArgs(&value) {
		return oneValueErr(d, option)
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return d.Errf("invalid boolean value for '%s': %v", option, err)
	}
	*dst = parsed
	return nil
}

// listArg reads the values of an option that takes one or more: the
// current key, or where it is, followed by any number of old ones.
func listArg(d *caddyfile.Dispenser, dst *[]string) error {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return d.ArgErr()
	}
	*dst = args
	return nil
}

// finishCaddyfile applies the Caddyfile's defaults and checks the options
// against each other once the whole block is read.
func (s3 *S3) finishCaddyfile(d *caddyfile.Dispenser) error {
	if s3.Region == "" {
		s3.Region = defaultRegion
	}
	if s3.Prefix == "" {
		s3.Prefix = "acme"
	}

	if s3.Host != "" && s3.Endpoint != "" {
		return d.Err("cannot specify both 'host' and 'endpoint' options")
	}
	if err := s3.checkConfig(); err != nil {
		return d.WrapErr(err)
	}
	if s3.Endpoint != "" {
		s3.UsePathStyle = true
	}
	return nil
}

var (
	_ caddy.Provisioner      = (*S3)(nil)
	_ caddy.StorageConverter = (*S3)(nil)
	_ caddyfile.Unmarshaler  = (*S3)(nil)

	_ zapcore.ObjectMarshaler = (*S3)(nil)
	_ fmt.Stringer            = (*S3)(nil)
	_ fmt.GoStringer          = (*S3)(nil)
)
