package pwd

import (
	"crypto/md5"
	"encoding/hex"
)

// Md5 md5
func Md5(plainText []byte) []byte {
	hash := md5.New()
	hash.Write(plainText)
	return []byte(hex.EncodeToString(hash.Sum(nil)))
}
