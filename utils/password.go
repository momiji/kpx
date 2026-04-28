package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// CreateKey generates a new random 256-byte encryption key.
func CreateKey() []byte {
	key := make([]byte, 256)
	rand.Read(key)
	return key
}

// ReadKey reads the encryption key from keyFile, creating and persisting it if absent.
func ReadKey(keyFile string) []byte {
	key, err := os.ReadFile(keyFile)
	if err == nil {
		return key
	}
	key = CreateKey()
	err = os.WriteFile(keyFile, key, 0600)
	if err != nil {
		panic(err)
	}
	return key
}

func keyHash(keyFile string) string {
	hasher := md5.New()
	hasher.Write(ReadKey(keyFile))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Encrypt encrypts data using AES-256-GCM with the key stored in keyFile.
func Encrypt(data, keyFile string) string {
	block, _ := aes.NewCipher([]byte(keyHash(keyFile)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts data using AES-256-GCM with the key stored in keyFile.
func Decrypt(data, keyFile string) (string, error) {
	encoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(keyHash(keyFile)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(encoded) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	decrypted, err := gcm.Open(nil, encoded[:nonceSize], encoded[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
