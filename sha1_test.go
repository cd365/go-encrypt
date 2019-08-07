package pwd

import (
	"testing"
)

// TestSha1 test sha1
func TestSha1(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText := Sha1(plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// BenchmarkSha1 benchmark sha1
func BenchmarkSha1(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		cipherText := Sha1(plainText)
		b.Log(cipherText)
	}
}
