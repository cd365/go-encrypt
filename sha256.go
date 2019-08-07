package pwd

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256 sha256
func Sha256(plainText []byte) []byte {
	hash := sha256.New()
	hash.Write(plainText)
	return []byte(hex.EncodeToString(hash.Sum(nil)))
}
