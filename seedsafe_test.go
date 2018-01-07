package seedsafe

import (
	"bytes"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	examples := []struct {
		Password string
		Text     string
	}{
		{
			"puck-outrage-stole-locale-brood",
			"habit flip route bus caught ribbon donkey enough feel next " +
				"drink mansion alcohol genuine perfect digital fresh frog " +
				"faculty then canoe absurd mouse magnet",
		},
		{
			"genus-illness-catbird-fondly-axis",
			"pizza kind pen alcohol over afraid demand gospel rotate attack " +
				"city right safe limb give cradle lava fiber coral donor " +
				"valve replace renew damp",
		},
		{
			"calico-pressman-enrage-birch-curlicue",
			"paper corn draft general test degree artist grow outdoor hockey " +
				"history marriage artist exist chief jump problem hedgehog " +
				"parrot life clutch toast river action",
		},
		{
			"faculty-satisfy-exorcist-metric-manx",
			"multiply filter tree amateur pumpkin online march illegal pact " +
				"enjoy paper special crisp alcohol explain device whale " +
				"sauce illness verify extend few garage oven",
		},
	}

	for _, e := range examples {
		encrypted1, err := Encrypt([]byte(e.Text), []byte(e.Password))
		if err != nil {
			t.Fatalf("Error during encryption: %s", err)
		}

		encrypted2, err := Encrypt([]byte(e.Text), []byte(e.Password))
		if err != nil {
			t.Fatalf("Error during encryption: %s", err)
		}

		decrypted1, err := Decrypt(encrypted1, []byte(e.Password))
		if err != nil {
			t.Fatalf("Error during decryption: %s", err)
		}

		decrypted2, err := Decrypt(encrypted2, []byte(e.Password))
		if err != nil {
			t.Fatalf("Error during decryption: %s", err)
		}

		if string(encrypted1) == string(encrypted2) {
			t.Fatal("Encrypt does not create unique output each time when " +
				"given identical inputs.")
		}

		if bytes.Contains(encrypted1, []byte(e.Text)) {
			t.Fatal("Encrypted string contain the unencrypted string.")
		}

		if string(decrypted1) != e.Text {
			t.Fatalf("\nExpected: %s\n     Got: %s", e.Text, decrypted1)
		}

		if len(decrypted1) != len(e.Text) {
			t.Fatalf("\nExpected length: %d\nGot: %d",
				len(e.Text), len(decrypted1))
		}

		if string(decrypted2) != e.Text {
			t.Fatalf("\nExpected: %s\n     Got: %s", e.Text, decrypted2)
		}

		if len(decrypted2) != len(e.Text) {
			t.Fatalf("\nExpected length: %d\nGot: %d",
				len(e.Text), len(decrypted2))
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
