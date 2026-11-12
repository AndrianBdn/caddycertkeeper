package caddycertkeeper

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"go.uber.org/zap"
)

// The options the encryption keys can come from. One of them at a time.
const (
	keysInConfig = "encryption_key"
	keysInFiles  = "encryption_key_file"
	keysInSSM    = "encryption_key_ssm"
)

// base64KeyPrefix marks a key written as the base64 of its 32 bytes.
const base64KeyPrefix = "base64:"

// ssmTimeout bounds reading all the encryption keys from Parameter Store.
const ssmTimeout = 30 * time.Second

// parseKey turns a key as it is configured into the key.
//
// A value of exactly 32 bytes is the key itself, as it has always been in
// certmagic-s3. Anything else must be "base64:" followed by the base64 of
// 32 bytes, which is the only way to write a key of 32 random bytes as
// text. The two cannot be confused: with the prefix, the base64 of 32 bytes
// is 50 characters or more. Both base64 alphabets are read, with or without
// padding.
//
// The errors describe the value and never repeat it.
func parseKey(value string) (key [keySize]byte, err error) {
	raw := []byte(value)
	if len(value) != keySize {
		encoded, ok := strings.CutPrefix(value, base64KeyPrefix)
		if !ok {
			return key, fmt.Errorf("must have exactly %d bytes, got %d, or be %q followed by the base64 of %d bytes",
				keySize, len(value), base64KeyPrefix, keySize)
		}

		encoded = strings.TrimRight(encoded, "=")
		encoded = strings.NewReplacer("-", "+", "_", "/").Replace(encoded)
		raw, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
		// The decoder skips line breaks; a key with one in it is a mistake.
		if err != nil || strings.ContainsAny(encoded, "\r\n") {
			return key, fmt.Errorf("is not valid base64 after %q", base64KeyPrefix)
		}
		if len(raw) != keySize {
			return key, fmt.Errorf("must be the base64 of exactly %d bytes, got %d", keySize, len(raw))
		}
	}

	copy(key[:], raw)
	if key == [keySize]byte{} {
		return key, errors.New("must not be all zero bytes")
	}
	return key, nil
}

// parseStoredKey turns the content of a key file or of an SSM parameter
// into the key. Content of exactly 32 bytes is the key, whatever the bytes
// are. Anything else is a key as it would be written in the config, and
// since what is written by a text editor or by echo ends in a line ending,
// one line ending is dropped from it.
func parseStoredKey(content string) ([keySize]byte, error) {
	if len(content) != keySize {
		content = strings.TrimSuffix(content, "\n")
	}
	if len(content) != keySize {
		content = strings.TrimSuffix(content, "\r")
	}
	return parseKey(content)
}

// keySource returns the option the encryption keys come from, or "" when
// there are none, and refuses uses of the key options that do not make
// sense.
func (s3 *S3) keySource() (string, error) {
	var sources []string
	if s3.EncryptionKey != "" {
		sources = append(sources, keysInConfig)
	}
	if len(s3.EncryptionKeyFile) > 0 {
		sources = append(sources, keysInFiles)
	}
	if len(s3.EncryptionKeySSM) > 0 {
		sources = append(sources, keysInSSM)
	}

	switch {
	case len(sources) > 1:
		return "", fmt.Errorf("%s are set together; use one of them", strings.Join(sources, " and "))
	case s3.EncryptionKey == "" && len(s3.OldEncryptionKeys) > 0:
		return "", errors.New("old encryption keys are set but encryption_key is empty")
	case len(sources) == 0:
		return "", nil
	}

	// At most one of the two lists has anything in it here.
	names := slices.Concat(s3.EncryptionKeyFile, s3.EncryptionKeySSM)
	if i := slices.Index(names, ""); i >= 0 {
		return "", fmt.Errorf("%s: name %d is empty", sources[0], i+1)
	}
	return sources[0], nil
}

// encryptionKeys returns the configured keys in order: the first encrypts,
// every one of them decrypts. No keys means clear text storage. Errors name
// a key by where it comes from, never by its value.
func (s3 *S3) encryptionKeys(ctx context.Context, cfg aws.Config) ([][keySize]byte, error) {
	source, err := s3.keySource()
	if err != nil {
		return nil, err
	}
	switch source {
	case keysInConfig:
		return s3.inlineKeys()
	case keysInFiles:
		return s3.fileKeys()
	case keysInSSM:
		client := s3.ssmClient
		if client == nil {
			client = s3.newSSMClient(cfg)
		}
		return s3.ssmKeys(ctx, client)
	}
	return nil, nil
}

// inlineKeys returns the keys written in the config itself.
func (s3 *S3) inlineKeys() ([][keySize]byte, error) {
	if s3.EncryptionKey == "" {
		return nil, nil
	}
	key, err := parseKey(s3.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encryption key %w", err)
	}
	keys := [][keySize]byte{key}
	for i, old := range s3.OldEncryptionKeys {
		key, err = parseKey(old)
		if err != nil {
			return nil, fmt.Errorf("old encryption key %d %w", i+1, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// fileKeys reads one key from each file named in EncryptionKeyFile.
func (s3 *S3) fileKeys() ([][keySize]byte, error) {
	keys := make([][keySize]byte, 0, len(s3.EncryptionKeyFile))
	for _, path := range s3.EncryptionKeyFile {
		// #nosec G304 -- the path is the operator's own configuration
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading encryption key file: %w", err)
		}
		key, err := parseStoredKey(string(content))
		if err != nil {
			return nil, fmt.Errorf("encryption key in file %q %w", path, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// newSSMClient builds the client the keys are read with. Keys are only
// read from AWS itself, over verified TLS: an endpoint override from the
// environment or the shared config (AWS_ENDPOINT_URL and the like) is
// dropped, and with keys in SSM the 'insecure' option never reaches cfg.
func (s3 *S3) newSSMClient(cfg aws.Config) *ssm.Client {
	return ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		o.BaseEndpoint = nil
	})
}

// ssmKeys reads one key from each parameter named in EncryptionKeySSM.
func (s3 *S3) ssmKeys(ctx context.Context, client *ssm.Client) ([][keySize]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ssmTimeout)
	defer cancel()

	keys := make([][keySize]byte, 0, len(s3.EncryptionKeySSM))
	for _, name := range s3.EncryptionKeySSM {
		var optFns []func(*ssm.Options)
		// A parameter given by ARN is read from the region the ARN names,
		// which need not be the bucket's.
		if parsed, err := arn.Parse(name); err == nil && parsed.Region != "" {
			optFns = append(optFns, func(o *ssm.Options) { o.Region = parsed.Region })
		}

		out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(true),
		}, optFns...)
		if err != nil {
			return nil, fmt.Errorf("reading encryption key from SSM parameter %q: %w", name, err)
		}
		if out.Parameter == nil {
			return nil, fmt.Errorf("reading encryption key from SSM parameter %q: empty response", name)
		}
		if out.Parameter.Type != ssmtypes.ParameterTypeSecureString {
			s3.Logger.Warn("encryption key is kept in an SSM parameter that is not a SecureString",
				zap.String("parameter", name),
				zap.String("type", string(out.Parameter.Type)),
			)
		}

		key, err := parseStoredKey(aws.ToString(out.Parameter.Value))
		if err != nil {
			return nil, fmt.Errorf("encryption key in SSM parameter %q %w", name, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// setupEncryption takes the keys encryptionKeys returned.
func (s3 *S3) setupEncryption(keys [][keySize]byte) {
	if len(keys) == 0 {
		s3.Logger.Info("Clear text certificate storage active")
		s3.iowrap = CleartextIO{}
		return
	}

	source, _ := s3.keySource()
	s3.Logger.Info("Encrypted certificate storage active",
		zap.Int("old_encryption_keys", len(keys)-1),
		zap.String("key_source", source),
	)
	s3.iowrap = NewSecretBoxIO(keys[0], keys[1:]...)
}
