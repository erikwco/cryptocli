package cryptocli

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

type Crypt struct {
	key string
	blk []byte
}

func New(key string, blk []byte) *Crypt {
	return &Crypt{key: key, blk: blk}
}

func (c Crypt) Encrypt(text string) (string, error) {
	// cipher block
	block, err := aes.NewCipher([]byte(c.key))
	if err != nil {
		return "", err
	}
	// string to byte
	plaintext := []byte(text)
	// CFB Encrypter
	cfb := cipher.NewCFBEncrypter(block, c.blk)
	cipherbuffer := make([]byte, len(plaintext))
	// encrypt
	cfb.XORKeyStream(cipherbuffer, plaintext)
	return c.toBase64(cipherbuffer), nil
}

func (c Crypt) toBase64(plaintext []byte) string {
	return base64.StdEncoding.EncodeToString(plaintext)
}

func (c Crypt) Decrypt(text string) (string, error) {
	// cipher block
	block, err := aes.NewCipher([]byte(c.key))
	if err != nil {
		return "", nil
	}

	// decode text
	cipherText := c.fromBase64(text)
	if cipherText == nil {
		return "", fmt.Errorf("value can't be decoded")
	}

	// CFB Decrypter
	cfb := cipher.NewCFBDecrypter(block, c.blk)

	// buffer
	plaintext := make([]byte, len(cipherText))
	cfb.XORKeyStream(plaintext, cipherText)
	return string(plaintext), nil
}

func (c Crypt) fromBase64(plaintext string) []byte {
	data, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return nil
	}
	return data
}
