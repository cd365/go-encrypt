package pwd

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
)

// Hmac hmac
func Hmac(key, data []byte) []byte {
	hash := hmac.New(md5.New, key)
	hash.Write(data)
	return []byte(hex.EncodeToString(hash.Sum([]byte(""))))
}
