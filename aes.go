package pwd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

/**
AES实现的方式多样, 其中包括ECB,CBC,CFB,OFB等

加密模式	    对应加解密方法
CBC         NewCBCDecrypter, NewCBCEncrypter
CTR	        NewCTR
CFB	        NewCFBDecrypter, NewCFBEncrypter
OFB	        NewOFB
*/

// AesCbcEncrypt aes cbc encrypt , The most common method of aes encryption
func AesCbcEncrypt(plainText, secretKey, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey) // NewCipher The function limits the length of the input k to 16,24 or 32
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()                 // gets the length of the block of the secret key
	plainText = PKCS7Padding(plainText, blockSize) // the completion code 补全码
	blockMode := cipher.NewCBCEncrypter(block, iv) // encryption mode
	crypt := make([]byte, len(plainText))          // create array
	blockMode.CryptBlocks(crypt, plainText)        // encode
	return []byte(base64.StdEncoding.EncodeToString(crypt)), nil
}

// AesCbcDecrypt aes cbc decrypt
func AesCbcDecrypt(cipherText, secretKey, iv []byte) ([]byte, error) {
	cryptByte, err := base64.StdEncoding.DecodeString(string(cipherText)) // to byte array
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secretKey) // group secret key
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv) // encryption mode
	plainText := make([]byte, len(cryptByte))      // create array
	blockMode.CryptBlocks(plainText, cryptByte)    // decode
	return PKCS7UnPadding(plainText), nil          // to completion 去补全码
}

// PKCS7Padding 补码
func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

// PKCS7UnPadding 去码
func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unPadding := int(plantText[length-1])
	return plantText[:(length - unPadding)]
}

// AesEcbEncrypt aes ecb encrypt
func AesEcbEncrypt(src, key []byte) (encrypted []byte, err error) {
	cipherText, err := aes.NewCipher(GenerateKey(key))
	if err != nil {
		return nil, err
	}
	length := (len(src) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, src)
	pad := byte(len(plain) - len(src))
	for i := len(src); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	// block encryption 分组分块加密
	for bs, be := 0, cipherText.BlockSize(); bs <= len(src); bs, be = bs+cipherText.BlockSize(), be+cipherText.BlockSize() {
		cipherText.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted, nil
}

// AesEcbDecrypt aes ecb decrypt
func AesEcbDecrypt(encrypted, key []byte) (decrypted []byte, err error) {
	cipherText, err := aes.NewCipher(GenerateKey(key))
	if err != nil {
		return nil, err
	}
	decrypted = make([]byte, len(encrypted))
	for bs, be := 0, cipherText.BlockSize(); bs < len(encrypted); bs, be = bs+cipherText.BlockSize(), be+cipherText.BlockSize() {
		cipherText.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}
	return decrypted[:trim], nil
}

// GenerateKey generate key
func GenerateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// AesCfbEncrypt aes cfb encrypt
func AesCfbEncrypt(plainText, secretKey, iv []byte) ([]byte, error) {
	if len(iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
	return cipherText, nil
}

func AesCfbDecrypt(cipherText, secretKey, iv []byte) ([]byte, error) {
	if len(iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		panic(err)
	}
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText, nil
}

// AesCtr aes ctr encrypt and decrypt
func AesCtr(text, key, iv []byte) ([]byte, error) {
	if len(iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	// 指定加密,解密算法为AES,返回一个AES的Block接口对象
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 指定分组模式
	blockMode := cipher.NewCTR(block, iv)
	// 执行加密,解密操作
	message := make([]byte, len(text))
	blockMode.XORKeyStream(message, text)
	// 返回明文或密文
	return message, nil
}

// AesOfb aes ofb encrypt and decrypt
func AesOfb(text, key, iv []byte) ([]byte, error) {
	if len(iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	// 指定加密,解密算法为AES,返回一个AES的Block接口对象
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 指定分组模式
	blockMode := cipher.NewOFB(block, iv)
	// 执行加密,解密操作
	message := make([]byte, len(text))
	blockMode.XORKeyStream(message, text)
	// 返回明文或密文
	return message, nil
}
