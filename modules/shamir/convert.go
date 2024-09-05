package shamir

import (
	"encoding/binary"
)

func KeyBytesToKeyUint16s(data []byte) []uint16 {
	// If the length is odd, append a 1 byte
	// If the length is even, append two zeros
	if len(data)%2 != 0 {
		data = append(data, 0x01)
	} else {
		data = append(data, 0x00)
		data = append(data, 0x00)
	}

	// Create a slice of uint16 with the appropriate length
	uint16s := make([]uint16, len(data)/2)

	// Convert each pair of bytes to a uint16
	for i := 0; i < len(data); i += 2 {
		uint16s[i/2] = binary.BigEndian.Uint16(data[i : i+2])
	}

	return uint16s
}

func KeyBytesToAESKeyUint16s(data []byte) [][]uint16 {
	// If the length is odd, append a 1 byte
	// If the length is even, append two zeros
	if len(data)%2 != 0 {
		data = append(data, 0x01)
	} else {
		data = append(data, 0x00)
		data = append(data, 0x00)
	}

	left := 16 - len(data)%16
	for i := 0; i < left; i++ {
		data = append(data, byte(left))
	}

	keyLen := len(data) / 16

	uint16Key := make([][]uint16, 0)
	for i := 0; i < keyLen; i++ {
		emptyKey := make([]uint16, 8)
		uint16Key = append(uint16Key, emptyKey)
	}

	keyData := make([]byte, 16)
	uint16s := make([]uint16, len(data)/2)

	for j := 0; j < keyLen; j++ {
		copy(keyData, data[j*16:(j+1)*16])
		// Convert each pair of bytes to a uint16
		for i := 0; i < 16; i += 2 {
			uint16s[i/2] = binary.BigEndian.Uint16(keyData[i : i+2])
		}
		copy(uint16Key[j], uint16s)
	}

	return uint16Key
}

func AESKeyUint16sToKeyBytes(data [][]uint16) []byte {
	uint16s := make([]uint16, 0)
	for _, d := range data {
		uint16s = append(uint16s, d...)
	}
	// Create a byte slice with twice the length of the uint16 slice
	bytes := make([]byte, len(uint16s)*2)

	// Convert each uint16 value to a pair of bytes
	for i, v := range uint16s {
		binary.BigEndian.PutUint16(bytes[i*2:(i+1)*2], v)
	}

	// First of all, get where the key ends
	endNum := bytes[len(bytes)-1]

	if bytes[len(bytes)-int(endNum)-1] == 1 {
		return bytes[:len(bytes)-int(endNum)-1]
	} else {
		return bytes[:len(bytes)-int(endNum)-2]
	}
}

func BytesToUint16s(data []byte) []uint16 {
	// If the length is odd, append a 1 byte
	// If the length is even, append two zeros
	if len(data)%2 != 0 {
		return nil
	}

	// Create a slice of uint16 with the appropriate length
	uint16s := make([]uint16, len(data)/2)

	// Convert each pair of bytes to a uint16
	for i := 0; i < len(data); i += 2 {
		uint16s[i/2] = binary.BigEndian.Uint16(data[i : i+2])
	}

	return uint16s
}

func Uint16sToBytes(uint16s []uint16) []byte {
	// Create a byte slice with twice the length of the uint16 slice
	bytes := make([]byte, len(uint16s)*2)

	// Convert each uint16 value to a pair of bytes
	for i, v := range uint16s {
		binary.BigEndian.PutUint16(bytes[i*2:], v)
	}

	return bytes
}

// This function removes the appended numbers at the end
func KeyUint16sToKeyBytes(uint16s []uint16) []byte {
	// Create a byte slice with twice the length of the uint16 slice
	bytes := make([]byte, len(uint16s)*2)

	// Convert each uint16 value to a pair of bytes
	for i, v := range uint16s {
		binary.BigEndian.PutUint16(bytes[i*2:], v)
	}

	if bytes[len(bytes)-1] == 1 {
		return bytes[:len(bytes)-1]
	} else {
		return bytes[:len(bytes)-2]
	}
}

func ConvertIndexUint16ToBytes(input uint16) []byte {
	// Create a byte slice of size 8
	byteSlice := make([]byte, 2)

	// Encode the integer to binary and store in byte slice
	binary.BigEndian.PutUint16(byteSlice, (input))

	// Return the byte slice representation of the integer
	return byteSlice
}
