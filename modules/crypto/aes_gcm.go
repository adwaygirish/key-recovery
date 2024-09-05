package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

func GetAESGCMEncryption(key,
	nonce, message, authData []byte) []byte {

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Pad the plaintext to the block size
	// paddedData := pad(message, aes.BlockSize)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, message, authData)

	return ciphertext
}

func GetAESGCMDecryption(key, nonce, ciphertext,
	authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, authData)
	if err != nil {
		panic(err.Error())
	}

	return plaintext, nil
}
