package pwd

import (
	"testing"
)

// TestBase64Encrypt test base64 encrypt
func TestBase64Encrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText := Base64Encrypt(plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
	plainText = []byte(``)
	cipherText = Base64Encrypt(plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// TestBase64Decrypt test base64 decrypt
func TestBase64Decrypt(t *testing.T) {
	plainText := []byte(`123456`)
	cipherText := Base64Encrypt(plainText)
	t.Log(cipherText)
	de, err := Base64Decrypt(cipherText)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(de)
}

// BenchmarkBase64Encrypt benchmark base64 encrypt
func BenchmarkBase64Encrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		en := Base64Encrypt(plainText)
		b.Log(en)
	}
}

// BenchmarkBase64Decrypt benchmark base64 decrypt
func BenchmarkBase64Decrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	en := Base64Encrypt(plainText)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		de, err := Base64Decrypt(en)
		if err != nil {
			b.Fatal(err)
		}
		b.Log(de)
	}
}
