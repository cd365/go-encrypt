package pwd

import (
	"testing"
)

// TestSha512 test sha512
func TestSha512(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText := Sha512(plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// BenchmarkSha512 benchmark sha512
func BenchmarkSha512(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		cipherText := Sha512(plainText)
		b.Log(cipherText)
	}
}
