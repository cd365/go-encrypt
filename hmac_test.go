package pwd

import (
	"testing"
)

// TestHmac test hmac
func TestHmac(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText := Hmac(plainText, plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// BenchmarkHmac bench mark hmac
func BenchmarkHmac(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		cipherText := Hmac(plainText, plainText)
		b.Log(cipherText)
	}
}
