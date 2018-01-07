package seedsafe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

// Encrypt a payload with given password.
func Encrypt(plaintext []byte, password []byte) (safe []byte, err error) {
	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}

	key := generateKey(password, salt)
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	return renderSafe(salt, ciphertext), nil
}

// Decrypt a payload with given password.
func Decrypt(safe []byte, password []byte) (plaintext []byte, err error) {
	salt, ciphertext, err := parseSafe(safe)
	if err != nil {
		return nil, err
	}

	key := generateKey(password, salt)

	plaintext, err = decrypt(ciphertext, key)
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

func renderSafe(salt, ciphertext []byte) (safe []byte) {
	safe = make([]byte, 1+len(salt)+len(ciphertext))
	safe[0] = byte(len(salt))
	copy(safe[1:], salt)
	copy(safe[1+len(salt):], ciphertext)

	return base64encode(safe)
}

func parseSafe(safe []byte) (salt []byte, ciphertext []byte, err error) {
	text, err := base64decode(safe)
	if err != nil {
		return nil, nil, err
	}

	saltLen := int(text[0])
	salt = text[1 : saltLen+1]
	ciphertext = text[saltLen+1:]

	return salt, ciphertext, nil
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
	return pbkdf2.Key(password, salt, 1048576, 32, sha512.New)
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
