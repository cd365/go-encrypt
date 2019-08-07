package pwd

import (
	"crypto/sha1"
	"encoding/hex"
)

// Sha1 sha1
func Sha1(plainText []byte) []byte {
	hash := sha1.New()
	hash.Write(plainText)
	return []byte(hex.EncodeToString(hash.Sum([]byte(""))))
}
