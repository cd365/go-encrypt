package pwd

import (
	"testing"
)

// TestSha256 test sha256
func TestSha256(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText := Sha256(plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// BenchmarkSha256 benchmark sha256
func BenchmarkSha256(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		cipherText := Sha256(plainText)
		b.Log(cipherText)
	}
}
