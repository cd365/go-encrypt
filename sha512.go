package pwd

import (
	"crypto/sha512"
	"encoding/hex"
)

// Sha512 sha512
func Sha512(plainText []byte) []byte {
	hash := sha512.New()
	hash.Write(plainText)
	return []byte(hex.EncodeToString(hash.Sum(nil)))
}
