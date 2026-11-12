package caddycertkeeper

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// NonceSize is the size of the nonce every encrypted object starts with.
	NonceSize = 24

	// keySize is the size of an encryption key, in bytes.
	keySize = 32
)

// IO turns the data of an object into what is stored for it, and back.
type IO interface {
	// Seal returns what is stored for plain.
	Seal(plain []byte) []byte
	// Open returns the data that stored was made from, and whether it took
	// an old key to get it.
	Open(stored []byte) (plain []byte, underOldKey bool, err error)
}

// CleartextIO stores objects as they are.
type CleartextIO struct{}

func (CleartextIO) Seal(plain []byte) []byte { return plain }

func (CleartextIO) Open(stored []byte) ([]byte, bool, error) { return stored, false, nil }

// SecretBoxIO stores an object as a random nonce followed by the object
// sealed with NaCl secretbox under that nonce.
type SecretBoxIO struct {
	// keys[0] seals. All of them are tried, in order, to open; the ones
	// after the first are old keys.
	keys [][keySize]byte
}

func NewSecretBoxIO(current [keySize]byte, old ...[keySize]byte) *SecretBoxIO {
	return &SecretBoxIO{keys: append([][keySize]byte{current}, old...)}
}

func (sb *SecretBoxIO) Seal(plain []byte) []byte {
	var nonce [NonceSize]byte
	_, _ = rand.Read(nonce[:]) // never fails

	out := make([]byte, NonceSize, NonceSize+len(plain)+secretbox.Overhead)
	copy(out, nonce[:])
	return secretbox.Seal(out, plain, &nonce, &sb.keys[0])
}

func (sb *SecretBoxIO) Open(stored []byte) ([]byte, bool, error) {
	if len(stored) == 0 {
		return nil, false, nil
	}
	if len(stored) < NonceSize {
		return nil, false, errors.New("insufficient data for decryption: missing nonce")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], stored[:NonceSize])

	// secretbox authenticates the data, so a wrong key fails cleanly and the
	// next one can be tried.
	for i := range sb.keys {
		if plain, ok := secretbox.Open(nil, stored[NonceSize:], &nonce, &sb.keys[i]); ok {
			return plain, i > 0, nil
		}
	}
	return nil, false, errors.New("decryption failed: invalid key or corrupted data")
}
