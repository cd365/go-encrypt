package pwd

import (
	"testing"
)

// TestAesCbcEncrypt test aes cbc encrypt
func TestAesCbcEncrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	cipherText, _ := AesCbcEncrypt(plainText, secretKey, iv)
	t.Log(cipherText)
	plainText = []byte(``)
	secretKey = []byte(`0123456789012345`)
	cipherText, _ = AesCbcEncrypt(plainText, secretKey, iv)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// TestAesCbcDecrypt test aes abc decrypt
func TestAesCbcDecrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	cipherText, _ := AesCbcEncrypt(plainText, secretKey, iv)
	t.Log(cipherText)
	t.Log(AesCbcDecrypt(cipherText, secretKey, iv))
}

// BenchmarkAesCbcEncrypt benchmark aes cbc encrypt
func BenchmarkAesCbcEncrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Log(AesCbcEncrypt(plainText, secretKey, iv))
	}
}

// BenchmarkAesCbcDecrypt benchmark aes cbc decrypt
func BenchmarkAesCbcDecrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	cipherText, _ := AesCbcEncrypt(plainText, secretKey, iv)
	b.Log(cipherText)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Log(AesCbcDecrypt(cipherText, secretKey, iv))
	}
}

// TestAesEcbEncrypt test aes ecb encrypt
func TestAesEcbEncrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	t.Log(plainText)
	secretKey := []byte(`0123456789012345`)
	cipherText, _ := AesEcbEncrypt(plainText, secretKey)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// TestAesEcbDecrypt test aes ecb decrypt
func TestAesEcbDecrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	t.Log(plainText)
	secretKey := []byte(`0123456789012345`)
	en, _ := AesEcbEncrypt(plainText, secretKey)
	t.Log(en)
	t.Log(AesEcbDecrypt(en, secretKey))
}

// BenchmarkAesEcbEncrypt benchmark aes ecb encrypt
func BenchmarkAesEcbEncrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		en, _ := AesEcbEncrypt(plainText, secretKey)
		b.Log(en)
	}
}

// BenchmarkAesEcbDecrypt benchmark aes ecb decrypt
func BenchmarkAesEcbDecrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	en, _ := AesEcbEncrypt(plainText, secretKey)
	b.Log(en)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Log(AesEcbDecrypt(en, secretKey))
	}
}

// TestAesCfbEncrypt test aes cfb encrypt
func TestAesCfbEncrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	cipherText, _ := AesCfbEncrypt(plainText, secretKey, iv)
	t.Log(cipherText)
	t.Log(string(cipherText))
}

// TestAesCfbDecrypt test aes cfb decrypt
func TestAesCfbDecrypt(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	t.Log(plainText)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	en, _ := AesCfbEncrypt(plainText, secretKey, iv)
	t.Log(en)
	de, err := AesCfbDecrypt(en, secretKey, iv)
	if err != nil {
		t.Log(err)
	}
	t.Log(de)
}

// BenchmarkAesCfbEncrypt benchmark aes cfb encrypt
func BenchmarkAesCfbEncrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		en, _ := AesCfbEncrypt(plainText, secretKey, iv)
		b.Log(en)
	}
}

// BenchmarkAesCfbDecrypt benchmark aes cfb decrypt
func BenchmarkAesCfbDecrypt(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	en, _ := AesCfbEncrypt(plainText, secretKey, iv)
	b.Log(en)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		de, err := AesCfbDecrypt(en, secretKey, iv)
		if err != nil {
			b.Log(err)
		}
		b.Log(de)
	}
}

// TestAesCtr test aes ctr
func TestAesCtr(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	t.Log(plainText)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	cipherText, _ := AesCtr(plainText, secretKey, iv)
	t.Log(cipherText)
	plain, _ := AesCtr(cipherText, secretKey, iv)
	t.Log(plain)
	t.Log(string(plain))
}

// BenchmarkAesCtr benchmark aes ctr
func BenchmarkAesCtr(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	en, _ := AesCtr(plainText, secretKey, iv)
	b.Log(en)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		de, err := AesCtr(en, secretKey, iv)
		if err != nil {
			b.Log(err)
		}
		b.Log(de)
	}
}

// TestAesOfb test aes ofb
func TestAesOfb(t *testing.T) {
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	t.Log(plainText)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	cipherText, _ := AesOfb(plainText, secretKey, iv)
	t.Log(cipherText)
	plain, _ := AesOfb(cipherText, secretKey, iv)
	t.Log(plain)
	t.Log(string(plain))
}

// BenchmarkAesOfb benchmark aes ofb
func BenchmarkAesOfb(b *testing.B) {
	b.StopTimer()
	plainText := []byte(`abcdefghijklmnopqrstuvwxyz`)
	secretKey := []byte(`0123456789012345`)
	iv := []byte(`1234567812345678`)
	en, _ := AesOfb(plainText, secretKey, iv)
	b.Log(en)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		de, err := AesOfb(en, secretKey, iv)
		if err != nil {
			b.Log(err)
		}
		b.Log(de)
	}
}
