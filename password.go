package kpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/howeyc/gopass"
	"io"
	"os"
)

func createKey() []byte {
	key := make([]byte, 256)
	rand.Read(key)
	return key
}

func readKey() []byte {
	key, err := os.ReadFile(options.KeyFile)
	if err == nil {
		return key
	}
	key = createKey()
	err = os.WriteFile(options.KeyFile, key, 0600)
	if err != nil {
		panic(err)
	}
	return key
}

func createHash() string {
	hasher := md5.New()
	hasher.Write(readKey())
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data string) string {
	block, _ := aes.NewCipher([]byte(createHash()))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	cipher := base64.StdEncoding.EncodeToString(ciphertext)
	return cipher
}

func decrypt(data string) (string, error) {
	encoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	key := []byte(createHash())
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encoded[:nonceSize], encoded[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func encryptPassword() {
	fmt.Printf("Encrypt a password - key location is `%s`\n", options.KeyFile)
	fmt.Print("Password: ")
	pwdBytes, err := gopass.GetPasswdMasked() // looks like password always exists even if error
	if err != nil {
		os.Exit(1)
	}
	fmt.Printf("Encrypted: %s%s\n", ENCRYPTED, encrypt(string(pwdBytes)))
	os.Exit(0)
}
