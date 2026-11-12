package caddycertkeeper

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"go.uber.org/zap"
)

// keySize is the size of an encryption key, in bytes.
const keySize = 32

// base64KeyPrefix marks a key written as the base64 of its 32 bytes.
const base64KeyPrefix = "base64:"

// parseKey turns a key as it is configured into the 32 bytes of the key.
//
// A value of exactly 32 bytes is the key itself, as it has always been in
// certmagic-s3. Anything else must be "base64:" followed by the base64 of
// 32 bytes, which is the only way to write a key of 32 random bytes as
// text. The two cannot be confused: with the prefix, the base64 of 32 bytes
// is 50 characters or more. Both base64 alphabets are read, with or without
// padding.
//
// The errors describe the value and never repeat it.
func parseKey(value string) (string, error) {
	if len(value) == keySize {
		return value, nil
	}
	encoded, ok := strings.CutPrefix(value, base64KeyPrefix)
	if !ok {
		return "", fmt.Errorf("must have exactly %d bytes, got %d, or be %q followed by the base64 of %d bytes",
			keySize, len(value), base64KeyPrefix, keySize)
	}

	encoded = strings.TrimRight(encoded, "=")
	encoded = strings.NewReplacer("-", "+", "_", "/").Replace(encoded)
	raw, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	// The decoder skips line breaks; a key with one in it is a mistake.
	if err != nil || strings.ContainsAny(encoded, "\r\n") {
		return "", fmt.Errorf("is not valid base64 after %q", base64KeyPrefix)
	}
	if len(raw) != keySize {
		return "", fmt.Errorf("must be the base64 of exactly %d bytes, got %d", keySize, len(raw))
	}
	return string(raw), nil
}

// SSMTimeout bounds reading all the encryption keys from Parameter Store.
var SSMTimeout = 30 * time.Second

// ssmAPI is the part of the SSM client used here.
type ssmAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// encryptionKeys returns the configured keys in order: the first encrypts,
// every one of them decrypts. No keys means clear text storage. Errors name
// a key by where it comes from, never by its value.
func (s3 *S3) encryptionKeys(ctx context.Context, cfg aws.Config) ([]string, error) {
	keys, err := s3.inlineKeys()
	if err != nil {
		return nil, err
	}

	switch {
	case len(s3.EncryptionKeyFile) > 0:
		return s3.fileKeys()
	case len(s3.EncryptionKeySSM) > 0:
		client := s3.ssmClient
		if client == nil {
			client = s3.newSSMClient(cfg)
		}
		return s3.ssmKeys(ctx, client)
	}
	return keys, nil
}

// keySource names where the encryption keys come from: "config", "file",
// "ssm", or nothing when there are none.
func (s3 *S3) keySource() string {
	switch {
	case s3.EncryptionKey != "":
		return "config"
	case len(s3.EncryptionKeyFile) > 0:
		return "file"
	case len(s3.EncryptionKeySSM) > 0:
		return "ssm"
	}
	return ""
}

// newSSMClient builds the client the keys are read with. The 'insecure'
// option is for the bucket's endpoint; the keys always come from AWS, and
// the connection they arrive on is always verified.
func (s3 *S3) newSSMClient(cfg aws.Config) *ssm.Client {
	return ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		if s3.Insecure {
			o.HTTPClient = awshttp.NewBuildableClient()
		}
	})
}

// inlineKeys returns the keys written in the config itself, and refuses
// combinations of the key options that do not make sense.
func (s3 *S3) inlineKeys() ([]string, error) {
	var sources []string
	if s3.EncryptionKey != "" {
		sources = append(sources, "encryption_key")
	}
	if len(s3.EncryptionKeyFile) > 0 {
		sources = append(sources, "encryption_key_file")
	}
	if len(s3.EncryptionKeySSM) > 0 {
		sources = append(sources, "encryption_key_ssm")
	}
	if len(sources) > 1 {
		return nil, fmt.Errorf("%s are set together; use one of them", strings.Join(sources, " and "))
	}

	if s3.EncryptionKey == "" {
		if len(s3.OldEncryptionKeys) > 0 {
			return nil, errors.New("old encryption keys are set but encryption_key is empty")
		}
		return nil, nil
	}

	key, err := parseKey(s3.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encryption key %w", err)
	}
	keys := []string{key}
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
//
// A file of exactly 32 bytes is the key, whatever the bytes are, and is
// never trimmed: the last byte of a random key may well be a newline.
// Any other file holds a key as it would be written in the config, a
// "base64:" one included, and since a file written by a text editor or by
// echo ends in a line ending, one line ending is dropped from it.
func (s3 *S3) fileKeys() ([]string, error) {
	keys := make([]string, 0, len(s3.EncryptionKeyFile))
	for i, path := range s3.EncryptionKeyFile {
		if path == "" {
			return nil, fmt.Errorf("encryption_key_file: file name %d is empty", i+1)
		}

		// #nosec G304 -- the path is the operator's own configuration
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading encryption key file: %w", err)
		}
		text := string(raw)
		if len(text) != keySize {
			if trimmed, ok := strings.CutSuffix(text, "\r\n"); ok {
				text = trimmed
			} else {
				text = strings.TrimSuffix(text, "\n")
			}
		}
		key, err := parseKey(text)
		if err != nil {
			return nil, fmt.Errorf("encryption key in file %q %w", path, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ssmKeys reads one key from each parameter named in EncryptionKeySSM.
func (s3 *S3) ssmKeys(ctx context.Context, client ssmAPI) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, SSMTimeout)
	defer cancel()

	keys := make([]string, 0, len(s3.EncryptionKeySSM))
	for i, name := range s3.EncryptionKeySSM {
		if name == "" {
			return nil, fmt.Errorf("encryption_key_ssm: parameter name %d is empty", i+1)
		}

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

		// A trailing newline is an artifact of how the value was stored.
		key, err := parseKey(strings.TrimRight(aws.ToString(out.Parameter.Value), "\r\n"))
		if err != nil {
			return nil, fmt.Errorf("encryption key in SSM parameter %q %w", name, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// setupEncryption takes keys already checked by encryptionKeys.
func (s3 *S3) setupEncryption(keys []string) {
	if len(keys) == 0 {
		s3.Logger.Info("Clear text certificate storage active")
		s3.iowrap = &CleartextIO{}
		return
	}

	sb := &SecretBoxIO{}
	copy(sb.SecretKey[:], keys[0])
	for _, old := range keys[1:] {
		var key [keySize]byte
		copy(key[:], old)
		sb.OldSecretKeys = append(sb.OldSecretKeys, key)
	}
	s3.Logger.Info("Encrypted certificate storage active",
		zap.Int("old_encryption_keys", len(sb.OldSecretKeys)),
		zap.String("key_source", s3.keySource()),
	)
	s3.iowrap = sb
}
