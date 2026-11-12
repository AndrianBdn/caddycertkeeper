package caddycertkeeper

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

var testKey32 = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

func assertNoError(t *testing.T, err error, operation string) {
	if err != nil {
		t.Errorf("%s failed: %v", operation, err)
	}
}

func assertError(t *testing.T, err error, expectedMsg, operation string) {
	if err == nil || !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("%s should fail with '%s', got error: %v", operation, expectedMsg, err)
	}
}

func TestSecretBoxIO(t *testing.T) {
	sb := NewSecretBoxIO(testKey32)
	msg := []byte("This is a very important message that shall be encrypted...")

	t.Run("seal then open", func(t *testing.T) {
		sealed := sb.Seal(msg)
		if bytes.Contains(sealed, msg) {
			t.Error("the message is readable in what was sealed")
		}
		if len(sealed) != NonceSize+len(msg)+secretbox.Overhead {
			t.Errorf("sealed %d bytes into %d", len(msg), len(sealed))
		}

		plain, underOldKey, err := sb.Open(sealed)
		assertNoError(t, err, "opening")
		if !bytes.Equal(plain, msg) || underOldKey {
			t.Errorf("opened %q, underOldKey = %v", plain, underOldKey)
		}
	})

	t.Run("every seal has its own nonce", func(t *testing.T) {
		if bytes.Equal(sb.Seal(msg), sb.Seal(msg)) {
			t.Error("sealing the same message twice gave the same bytes")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		plain, _, err := sb.Open(sb.Seal(nil))
		assertNoError(t, err, "opening a sealed empty message")
		if len(plain) != 0 {
			t.Errorf("opened %q", plain)
		}

		// An object with nothing in it is read as empty, not as an error.
		plain, _, err = sb.Open(nil)
		assertNoError(t, err, "opening nothing")
		if len(plain) != 0 {
			t.Errorf("opened %q", plain)
		}
	})

	t.Run("data that cannot be opened", func(t *testing.T) {
		_, _, err := sb.Open([]byte("short")) // less than a nonce
		assertError(t, err, "insufficient data for decryption", "opening short data")

		tampered := sb.Seal(msg)
		tampered[len(tampered)-1] ^= 1
		_, _, err = sb.Open(tampered)
		assertError(t, err, "decryption failed", "opening tampered data")
	})
}

func TestSecretBoxIO_OldKeys(t *testing.T) {
	sb := NewSecretBoxIO(keyOf(testKeyA), keyOf(testKeyB), keyOf(testKeyC))
	for i, key := range []string{testKeyA, testKeyB, testKeyC} {
		got, underOldKey, err := sb.Open(NewSecretBoxIO(keyOf(key)).Seal([]byte("hello")))
		if err != nil || string(got) != "hello" {
			t.Errorf("data sealed with key %c: got %q, %v", key[0], got, err)
		}
		if underOldKey != (i > 0) {
			t.Errorf("data sealed with key %c: underOldKey = %v", key[0], underOldKey)
		}
	}

	// What is written is sealed with the first key only.
	if _, _, err := NewSecretBoxIO(keyOf(testKeyB)).Open(sb.Seal([]byte("hello"))); err == nil {
		t.Error("an old key opens what was just sealed")
	}

	_, _, err := sb.Open(NewSecretBoxIO(keyOf("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")).Seal([]byte("hello")))
	assertError(t, err, "decryption failed", "decrypting with no matching key")
}

func TestCleartextIO(t *testing.T) {
	ci := CleartextIO{}
	data := []byte("plain text data")

	if stored := ci.Seal(data); !bytes.Equal(stored, data) {
		t.Errorf("Seal() = %q, want %q", stored, data)
	}
	plain, underOldKey, err := ci.Open(data)
	if err != nil || !bytes.Equal(plain, data) || underOldKey {
		t.Errorf("Open() = %q, %v, %v", plain, underOldKey, err)
	}
}
