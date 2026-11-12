package caddycertkeeper

import (
	"bytes"
	"slices"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// keyOf is the key that 32 bytes of text are.
func keyOf(s string) (k [keySize]byte) {
	copy(k[:], s)
	return k
}

func keysOf(keys ...string) [][keySize]byte {
	out := make([][keySize]byte, len(keys))
	for i, k := range keys {
		out[i] = keyOf(k)
	}
	return out
}

// boxKeys returns the keys a storage encrypts with: the current one, then
// the old ones.
func boxKeys(t *testing.T, s *S3) [][keySize]byte {
	t.Helper()
	sb, ok := s.iowrap.(*SecretBoxIO)
	if !ok {
		t.Fatalf("storage is not encrypted: iowrap is a %T", s.iowrap)
	}
	return sb.keys
}

// bufferLogger logs JSON lines into the buffer it returns.
func bufferLogger() (*zap.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buf), zapcore.DebugLevel)
	return zap.New(core), &buf
}

func sorted(keys []string) []string {
	return slices.Sorted(slices.Values(keys))
}
