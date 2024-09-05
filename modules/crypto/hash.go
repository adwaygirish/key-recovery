package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// **************************************************************************
// **************************************************************************

// GetSHA256 returns the SHA256 hash of an input as a string
func GetSHA256String(inputString string) string {
	input := []byte(inputString)

	// Create a new SHA-256 hash
	hash := sha256.Sum256(input)

	// Print the hash as a hexadecimal string
	return hex.EncodeToString(hash[:])
}

// Converts a secret key to string
func ConvertKeyToString(k kyber.Scalar) string {
	return fmt.Sprintf("%s", k)
}

// Checks if two secret keys are k
func CheckRecSecretKeyString(baseHash string, k kyber.Scalar) bool {
	obtainedKeyString := ConvertKeyToString(k)
	obtainedKeyHash := GetSHA256String(obtainedKeyString)
	return baseHash == obtainedKeyHash
}

// ***************SHA 256 evaluation*****************************************
// **************************************************************************
// Evaluates the sha256 hash and returns it as []byte
func GetSHA256(input []byte) [32]byte {
	hash := sha256.Sum256(input)
	return hash
}

// Evaluates the sha256 hash of a point in F and returns it as []byte
func GetValSHA256(k kyber.Scalar) [32]byte {
	bytesVal := ConvertKeyToBytes(k)
	bytesHash := GetSHA256(bytesVal)
	return bytesHash
}

// Evaluates the sha256 hash of a share and returns it as []byte
func GetShareSHA256(shareVal *share.PriShare) [32]byte {
	bytesShare := ConvertShareToBytes(shareVal)
	bytesHash := GetSHA256(bytesShare)
	return bytesHash
}

func GetHashMatch(
	hashesSlice [][32]byte,
	recovered kyber.Scalar,
	largestShareSetSize int) (bool, [32]byte, *share.PriShare) {
	var outputFlag bool
	var outputHash [32]byte
	var outputShare *share.PriShare
	for _, hash := range hashesSlice {
		outputHash = hash
		outputFlag, outputShare = CheckRecShare(hash,
			recovered, largestShareSetSize)
		if outputFlag {
			break
		}
	}
	return outputFlag, outputHash, outputShare
}

// Function for generating salted hash for share packets
func GetSaltedHash(
	salt [32]byte,
	secret []byte) [32]byte {
	var totalData []byte
	totalData = append(totalData, secret...)
	for _, s := range salt {
		totalData = append(totalData, s)
	}
	hash := GetSHA256(totalData)
	return hash
}

// **************************************************************************
// **************************************************************************

// Given two sets of hashes,
// Find the difference between the two sets
func GetHashesSetDifference(hashes1, hashes2 [][32]byte) ([][32]byte, error) {
	var outputHashes [][32]byte
	for _, hash1 := range hashes1 {
		inFlag := false
		for _, hash2 := range hashes2 {
			if CheckHashesEqual(hash1, hash2) {
				inFlag = true
				break
			}
		}
		if !inFlag {
			outputHashes = append(outputHashes, hash1)
		}
	}
	return outputHashes, nil
}

// Given two sets of marker info,
// Find the difference between the two sets
func GetMarkerInfoDifference(markerInfo1, markerInfo2 [][]byte) ([][]byte,
	error) {
	var outputMarkerInfo [][]byte
	for _, bytes1 := range markerInfo1 {
		inFlag := false
		for _, bytes2 := range markerInfo2 {
			if CheckByteArrayEqual(bytes1, bytes2) {
				inFlag = true
				break
			}
		}
		if !inFlag {
			outputMarkerInfo = append(outputMarkerInfo, bytes1)
		}
	}
	return outputMarkerInfo, nil
}
