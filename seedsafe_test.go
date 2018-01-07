package seedsafe

import (
	"fmt"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	examples := []struct {
		Password string
		Text     string
	}{
		{
			"puck-outrage-stole-locale-brood",
			"tundra thiamine actinium cray gushy grainy lets ruminant edging " +
				"bunting embalm railhead purify swatch times added graham " +
				"friction blast liniment iberian octet yank suddenly",
		},
	}

	for _, e := range examples {
		encrypted, err := Encrypt([]byte(e.Text), []byte(e.Password))
		if err != nil {
			t.Fatalf("Error during encryption: %s", err)
		}

		decrypted, err := Decrypt(encrypted, []byte(e.Password))
		if err != nil {
			t.Fatalf("Error during decryption: %s", err)
		}

		fmt.Println(e.Text)
		fmt.Println(string(encrypted))
		fmt.Println(string(decrypted))

		if string(decrypted) != e.Text {
			t.Fatalf("\nExpected: %s\n     Got: %s", e.Text, decrypted)
		}

		if len(decrypted) != len(e.Text) {
			t.Fatalf("\nExpected length: %d\nGot: %d",
				len(e.Text), len(decrypted))
		}
	}
}

func TestRandomBytes(t *testing.T) {
	examples := []int{2, 4, 8, 16, 32, 64, 128, 256, 512}

	for _, n := range examples {
		salt, _ := randomBytes(n)
		if len(salt) != n {
			t.Fatalf("%d length expected, got %d", n, len(salt))
		}
	}
}

func TestGenerateKey(t *testing.T) {
	salt, _ := randomBytes(32)
	password := []byte("hello")
	key := generateKey(password, salt)

	if len(key) != 32 {
		t.Fatalf("Key length should be 256, but it is %d", len(key))
	}
}
