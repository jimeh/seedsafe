package seedsafe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

// Sep is the separator used to split salt and ciphertext.
var Sep = []byte("|")

// Encrypt a payload with given password.
func Encrypt(plaintext []byte, password []byte) ([]byte, error) {
	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}

	key := generateKey(password, salt)
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	output := base64encode(salt)
	output = append(output, Sep...)
	output = append(output, base64encode(ciphertext)...)
	return output, nil
}

// Decrypt a payload with given password.
func Decrypt(text []byte, password []byte) ([]byte, error) {
	separated := bytes.Split(text, Sep)
	salt, err := base64decode(separated[0])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64decode(separated[1])
	if err != nil {
		return nil, err
	}

	key := generateKey(password, salt)

	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(
		nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func generateKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 65536, 32, sha512.New)
}

func base64encode(input []byte) []byte {
	output := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(output, input)

	return output
}

func base64decode(input []byte) ([]byte, error) {
	output := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	l, err := base64.StdEncoding.Decode(output, input)
	if err != nil {
		return nil, err
	}

	return output[:l], nil
}
