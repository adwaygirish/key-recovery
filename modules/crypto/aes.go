package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// **************************************************************************
// **************************************************************************

// ****************************AES Encryption********************************
// **************************************************************************
// PKCS7 padding function
func pad(src []byte, blockSize int) []byte {
	padding := 0
	if len(src)%blockSize == 0 {
		padding = blockSize
	} else {
		// Get the length of the padding needed
		padding = blockSize - len(src)%blockSize
		// The padding is basically the length of the padding repeated that
		// number of times
	}
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	output := append(src, padText...)
	return output
}

func GetAESEncryption(key []byte, data []byte) []byte {

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Pad the plaintext to the block size
	paddedData := pad(data, aes.BlockSize)

	// Encrypt the padded plaintext
	// Ciphertext will contain the IV and the encryption of the data
	ciphertext := make([]byte, aes.BlockSize+len(paddedData))
	iv := ciphertext[:aes.BlockSize] // Initialization vector
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedData)

	return ciphertext
}

// ****************************AES Decryption********************************
// **************************************************************************
// GetAESDecrypted decrypts given text in AES 256 CBC
func GetAESDecryption(key, ciphertext []byte) ([]byte, bool, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, false, err
	}

	iv := ciphertext[:aes.BlockSize][:]
	data := ciphertext[aes.BlockSize:][:]

	if len(data)%aes.BlockSize != 0 {
		return nil, false, fmt.Errorf("data size has to be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	plaintext, validity := unpad(data, aes.BlockSize)

	return plaintext, validity, nil
}

// unpad removes PKCS7 padding from the data
func unpad(data []byte, blockSize int) ([]byte, bool) {
	padding := int(data[len(data)-1])
	offsetDifference := padding
	if padding > blockSize {
		offsetDifference = 0
	} else {
		for _, d := range data[len(data)-padding:] {
			if d != byte(padding) {
				// fmt.Println("here", d, padding)
				// fmt.Println(data)
				offsetDifference = 0
				break
			}
		}
	}
	return data[:len(data)-offsetDifference], true
}
