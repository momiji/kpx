package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keyFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.key")
}

// CreateKey

func TestCreateKey_Length(t *testing.T) {
	key := CreateKey()
	if len(key) != 256 {
		t.Fatalf("expected 256 bytes, got %d", len(key))
	}
}

func TestCreateKey_Randomness(t *testing.T) {
	a, b := CreateKey(), CreateKey()
	if string(a) == string(b) {
		t.Fatal("two keys should not be identical")
	}
}

// ReadKey

func TestReadKey_CreatesFileWhenAbsent(t *testing.T) {
	kf := keyFile(t)
	key := ReadKey(kf)
	if len(key) != 256 {
		t.Fatalf("expected 256-byte key, got %d", len(key))
	}
	if _, err := os.Stat(kf); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
}

func TestReadKey_FileHasRestrictedPermissions(t *testing.T) {
	kf := keyFile(t)
	ReadKey(kf)
	info, err := os.Stat(kf)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600, got %04o", perm)
	}
}

func TestReadKey_ReturnsSameKeyOnSubsequentReads(t *testing.T) {
	kf := keyFile(t)
	first := ReadKey(kf)
	second := ReadKey(kf)
	if string(first) != string(second) {
		t.Fatal("ReadKey should return the same key on subsequent calls")
	}
}

func TestReadKey_ReadsExistingFile(t *testing.T) {
	kf := keyFile(t)
	preset := make([]byte, 256)
	for i := range preset {
		preset[i] = byte(i)
	}
	if err := os.WriteFile(kf, preset, 0600); err != nil {
		t.Fatal(err)
	}
	key := ReadKey(kf)
	if string(key) != string(preset) {
		t.Fatal("ReadKey did not return the pre-existing key")
	}
}

// Encrypt / Decrypt round-trips

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	kf := keyFile(t)
	plaintext := "super secret password"
	enc := Encrypt(plaintext, kf)
	dec, err := Decrypt(enc, kf)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if dec != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, dec)
	}
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	kf := keyFile(t)
	enc := Encrypt("", kf)
	dec, err := Decrypt(enc, kf)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if dec != "" {
		t.Fatalf("expected empty string, got %q", dec)
	}
}

func TestEncryptDecrypt_UnicodeString(t *testing.T) {
	kf := keyFile(t)
	plaintext := "пароль 🔑"
	enc := Encrypt(plaintext, kf)
	dec, err := Decrypt(enc, kf)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if dec != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, dec)
	}
}

func TestEncrypt_ProducesBase64(t *testing.T) {
	kf := keyFile(t)
	enc := Encrypt("test", kf)
	if strings.ContainsAny(enc, " \t\n") {
		t.Fatal("encrypted output should be valid base64 with no whitespace")
	}
}

func TestEncrypt_DifferentNonceEachCall(t *testing.T) {
	kf := keyFile(t)
	a := Encrypt("same", kf)
	b := Encrypt("same", kf)
	if a == b {
		t.Fatal("two encryptions of the same plaintext should differ due to random nonce")
	}
}

func TestDecrypt_FailsWithWrongKey(t *testing.T) {
	kf1 := keyFile(t)
	kf2 := keyFile(t)
	enc := Encrypt("secret", kf1)
	_, err := Decrypt(enc, kf2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestDecrypt_FailsOnCorruptedCiphertext(t *testing.T) {
	kf := keyFile(t)
	enc := Encrypt("secret", kf)
	// flip a character in the middle
	corrupted := enc[:5] + "AAAA" + enc[9:]
	_, err := Decrypt(corrupted, kf)
	if err == nil {
		t.Fatal("expected error decrypting corrupted ciphertext")
	}
}

func TestDecrypt_FailsOnInvalidBase64(t *testing.T) {
	kf := keyFile(t)
	_, err := Decrypt("not-valid-base64!!!", kf)
	if err == nil {
		t.Fatal("expected error on invalid base64 input")
	}
}

func TestDecrypt_FailsOnTruncatedInput(t *testing.T) {
	kf := keyFile(t)
	_, err := Decrypt("aGk=", kf) // "hi" in base64 — too short to contain a nonce
	if err == nil {
		t.Fatal("expected error on truncated ciphertext")
	}
}
