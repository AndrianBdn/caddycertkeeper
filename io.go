package caddycertkeeper

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	NonceSize = 24
)

type IO interface {
	WrapReader(io.Reader) io.Reader
	ByteReader([]byte) Reader
}

type Reader struct {
	r   io.ReadSeeker
	l   int64
	err error
}

func (r *Reader) Read(buf []byte) (int, error) {
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	return r.r.Read(buf)
}

func (r *Reader) Len() int64 {
	return r.l
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	if r.err != nil {
		return 0, r.err
	}
	return r.r.Seek(offset, whence)
}

type CleartextIO struct{}

func (ci *CleartextIO) WrapReader(r io.Reader) io.Reader {
	return r
}

func (ci *CleartextIO) ByteReader(buf []byte) Reader {
	return Reader{bytes.NewReader(buf), int64(len(buf)), nil}
}

type SecretBoxIO struct {
	// SecretKey encrypts everything written and is tried first when reading.
	SecretKey [32]byte
	// OldSecretKeys are tried in order when SecretKey does not decrypt the
	// data. They are never used to encrypt.
	OldSecretKeys [][32]byte
}

func NewSecretBoxIO(key [32]byte) *SecretBoxIO {
	return &SecretBoxIO{SecretKey: key}
}

func (sb *SecretBoxIO) IsValid() bool {
	var zero [32]byte
	return sb.SecretKey != zero
}

func (sb *SecretBoxIO) makeNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return nonce, err
}

func (sb *SecretBoxIO) WrapReader(r io.Reader) io.Reader {
	if !sb.IsValid() {
		return &Reader{nil, 0, errors.New("SecretBoxIO not properly initialized")}
	}

	allData, err := io.ReadAll(r)
	if err != nil {
		return &Reader{nil, 0, err}
	}

	bout, _, err := sb.open(allData)
	if err != nil {
		return &Reader{nil, 0, err}
	}
	return bytes.NewReader(bout)
}

// open decrypts data and reports which key opened it: 0 for SecretKey, n
// for the nth of OldSecretKeys.
func (sb *SecretBoxIO) open(data []byte) ([]byte, int, error) {
	if !sb.IsValid() {
		return nil, 0, errors.New("SecretBoxIO not properly initialized")
	}
	if len(data) == 0 {
		return nil, 0, nil
	}
	if len(data) < NonceSize {
		return nil, 0, errors.New("insufficient data for decryption: missing nonce")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], data[:NonceSize])
	encryptedData := data[NonceSize:]

	// secretbox authenticates the data, so a wrong key fails cleanly and the
	// next one can be tried.
	if bout, ok := secretbox.Open(nil, encryptedData, &nonce, &sb.SecretKey); ok {
		return bout, 0, nil
	}
	for i := range sb.OldSecretKeys {
		if bout, ok := secretbox.Open(nil, encryptedData, &nonce, &sb.OldSecretKeys[i]); ok {
			return bout, i + 1, nil
		}
	}
	return nil, 0, errors.New("decryption failed: invalid key or corrupted data")
}

func (sb *SecretBoxIO) ByteReader(msg []byte) Reader {
	if !sb.IsValid() {
		return Reader{nil, 0, errors.New("SecretBoxIO not properly initialized")}
	}

	nonce, err := sb.makeNonce()
	if err != nil {
		return Reader{nil, 0, err}
	}

	out := make([]byte, NonceSize, NonceSize+len(msg)+secretbox.Overhead)
	copy(out, nonce[:])

	out = secretbox.Seal(out, msg, &nonce, &sb.SecretKey)
	return Reader{bytes.NewReader(out), int64(len(out)), nil}
}

var _ io.ReadSeeker = (*Reader)(nil)
