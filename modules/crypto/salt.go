package crypto

import (
	"crypto/rand"
	"log"
)

// ***************Generating Salts*******************************************
// **************************************************************************
// GenerateSalt generates a random salt of the given size
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	return salt, err
}

// GenerateSalt32 provides a salt of 32 bytes (relevant for SHA256)
func GenerateSalt32() ([32]byte, error) {
	var outputSalt [32]byte
	salt, err := GenerateSalt(32)
	if err != nil {
		log.Fatal("Error in salt generation")
	}
	copy(outputSalt[:], salt)
	return outputSalt, err
}

// GenerateRandomBytes generates n random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
