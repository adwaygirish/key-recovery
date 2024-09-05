package crypto

import (
	"bytes"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// **************************************************************************
// **************************************************************************

// ************Functions for finding the equality of datatypes***************
// **************************************************************************
// CheckHashesEqual compares two SHA-256 hashes for equality
func CheckHashesEqual(
	hash1,
	hash2 [32]byte) bool {
	return bytes.Compare(hash1[:], hash2[:]) == 0
}

// This function checks if the kyber.Scalar values are equal
func CheckValuesEqual(v1, v2 kyber.Scalar) bool {
	return v1.Equal(v2)
}

// Checks if two secret keys are equal
func CheckRecSecretKey(
	baseHash [32]byte,
	k kyber.Scalar) bool {
	obtainedKeyBytes := ConvertKeyToBytes(k)
	obtainedKeyHash := GetSHA256(obtainedKeyBytes)
	return CheckHashesEqual(baseHash, obtainedKeyHash)
}

func CheckRecShare(
	baseHash [32]byte,
	k kyber.Scalar,
	largestShareSetSize int) (bool, *share.PriShare) {
	for i := 0; i < largestShareSetSize; i++ {
		shareVal := &share.PriShare{I: i, V: k}
		obtainedKeyHash := GetShareSHA256(shareVal)
		if CheckHashesEqual(baseHash, obtainedKeyHash) {
			return true, shareVal
		}
	}
	return false, nil
}

func CheckCoordinatesEquality(subset []*share.PriShare) bool {
	for i := 0; i < len(subset); i++ {
		for j := i + 1; j < len(subset); j++ {
			if subset[i].I == subset[j].I {
				return false
			}
		}
	}
	return true
}

func CheckByteArrayEqual(
	bytes1,
	bytes2 []byte) bool {
	return bytes.Compare(bytes1, bytes2) == 0
}
