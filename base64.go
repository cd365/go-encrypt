package pwd

import (
	"encoding/base64"
)

// Base64Encrypt base64 encrypt
func Base64Encrypt(plainText []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(plainText))
}

// Base64Decrypt base64 decrypt
func Base64Decrypt(cipherText []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(cipherText))
}
