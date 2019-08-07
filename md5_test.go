package pwd

import (
	"testing"
)

// TestMd5 test md5
func TestMd5(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	cipherText := Md5(plainText)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// BenchmarkMd5 benchmark md5
func BenchmarkMd5(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		cipherText := Md5(plainText)
		b.Log(cipherText)
	}
}
