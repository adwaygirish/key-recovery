package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strconv"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// **************************************************************************
// **************************************************************************

// ***************Converting datatypes to []byte*********************
// **************************************************************************
// Converts a secret key to []byte
func ConvertKeyToBytes(k kyber.Scalar) []byte {
	writer := new(bytes.Buffer)
	_, err := k.MarshalTo(writer)
	if err != nil {
		log.Fatal("Cannot marshal the secret key")
	}
	output, ok := io.ReadAll(writer)
	if ok != nil {
		log.Fatal("Failed to convert to []byte.")
		return nil
	}
	return output
}

func ConvertIndexToBytes(input int) []byte {
	// Create a byte slice of size 8
	byteSlice := make([]byte, 8)

	// Encode the integer to binary and store in byte slice
	binary.BigEndian.PutUint64(byteSlice, uint64(input))

	// Return the byte slice representation of the integer
	return byteSlice
}

func ConvertShareToBytes(shareVal *share.PriShare) []byte {
	bytesInd := ConvertIndexToBytes((shareVal.I))
	bytesVal := ConvertKeyToBytes((shareVal.V))
	bytesShare := append(bytesInd, bytesVal...)
	return bytesShare
}

func ConvertBytesToIndex(byteSlice []byte) int {
	// Decode the byte slice as a big-endian uint64 integer
	return int(binary.BigEndian.Uint64(byteSlice))
}

// **************************************************************************
// **************************************************************************

// ****************************For Large Secrets*****************************
// **************************************************************************

func ConvertString256ToBytes(bitString string) ([]byte, error) {
	if len(bitString) > 256 {
		return nil, fmt.Errorf("string longer than 256")
	}
	var byteSlice []byte

	// Iterate over the bit string in chunks of 8 bits
	for i := 0; i < len(bitString); i += 8 {
		// Extract the current chunk of 8 bits
		end := i + 8
		if end > len(bitString) {
			end = len(bitString)
		}
		chunk := bitString[i:end]

		// Convert the chunk to a byte
		var byteVal byte
		for j := 0; j < len(chunk); j++ {
			byteVal = byteVal << 1
			if chunk[j] == '1' {
				byteVal |= 1
			}
		}

		// Append the byte to the byte slice
		byteSlice = append(byteSlice, byteVal)
	}

	return byteSlice, nil
}

func ConvertBitStringToBytes(bitstring string) [][]byte {
	var output [][]byte
	var outputString []string
	datasize := 240
	noOfSlices := len(bitstring) / datasize
	// break the bitstring into blocks of size 240
	for i := 0; i < noOfSlices; i++ {
		element := bitstring[i*datasize : (i+1)*datasize]
		outputString = append(outputString, (element))
	}
	// if there are some leftover bits,
	// then add them to the
	if len(bitstring)%datasize != 0 {
		leftString := bitstring[noOfSlices*datasize:]
		lenLeftString := len(leftString)
		strLenLeftString := strconv.FormatInt(int64(lenLeftString), 2)
		noOfBitsLeft := 256 - lenLeftString - len(strLenLeftString)
		padBits := ""
		for i := 0; i < noOfBitsLeft; i++ {
			padBits = padBits + "0"
		}
		lastString := leftString + padBits + strLenLeftString
		outputString = append(outputString, lastString)
	}

	for _, substring := range outputString {
		subOutput, err := ConvertString256ToBytes(substring)
		if err != nil {
			log.Fatalln("string can't be converted")
		}
		output = append(output, subOutput)
	}

	// convert the strings to []byte
	return output
}

// **************************************************************************
// **************************************************************************
