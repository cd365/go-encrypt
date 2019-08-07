package pwd

import (
	"encoding/base64"
	"testing"
)

// TestRsaEncrypt test rsa encrypt
func TestRsaEncrypt(t *testing.T) {
	plainText, _ := RsaEncrypt([]byte("hello world 1"), []byte(""))
	t.Log(plainText)
}

// TestRsaDecrypt test rsa decrypt
func TestRsaDecrypt(t *testing.T) {
	plainText, _ := RsaEncrypt([]byte("hello world 2"), []byte(""))
	t.Log(base64.StdEncoding.EncodeToString(plainText))
	cipherText, _ := RsaDecrypt(plainText, []byte(""))
	t.Log(string(cipherText))
}

// BenchmarkRsaEncrypt benchmark rsa encrypt
func BenchmarkRsaEncrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		cipherText, err := RsaEncrypt(plainText, []byte(""))
		if err != nil {
			b.Fatal(err)
		}
		b.Log(cipherText)
	}
}

// BenchmarkRsaDecrypt benchmark rsa decrypt
func BenchmarkRsaDecrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText, err := RsaEncrypt(plainText, []byte(""))
	if err != nil {
		b.Log(cipherText)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		plain, err := RsaDecrypt(cipherText, []byte(""))
		if err != nil {
			b.Fatal(err)
		}
		b.Log(plain)
	}
}
