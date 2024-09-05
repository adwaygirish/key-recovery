package crypto

import (
	"crypto/cipher"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// **************************************************************************
// **************************************************************************

// **********Relevant functions for additive anonymity packets***************
// **************************************************************************
func GetAdditiveIndisShareMatch(recovered kyber.Scalar,
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte) (bool, [32]byte, error) {
	var correctHash [32]byte
	bytesVal := ConvertKeyToBytes(recovered)
	saltedHash := GetSaltedHash(runRelevantSalt, bytesVal)
	isContainedHash := false
	for _, runRelevantHash := range runRelevantHashes {
		if CheckHashesEqual(saltedHash, runRelevantHash) {
			correctHash = saltedHash
			isContainedHash = true
			break
		}
	}

	return (isContainedHash), correctHash, nil
}

func GetAdditiveSaltedHashMatch(g kyber.Group, randSeedShares cipher.Stream,
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte,
	obtainedSubsecrets []kyber.Scalar) (bool, kyber.Scalar) {
	recoveredKey := g.Scalar().Pick(randSeedShares)
	recoveredKey = recoveredKey.Set(obtainedSubsecrets[0])
	for _, obtainedSubsecret := range obtainedSubsecrets[1:] {
		recoveredKey = recoveredKey.Add(recoveredKey, obtainedSubsecret)
	}
	obtainedKeyBytes := ConvertKeyToBytes(recoveredKey)
	saltedHash := GetSaltedHash(runRelevantSalt, obtainedKeyBytes)
	for _, runRelevantHash := range runRelevantHashes {
		if CheckHashesEqual(saltedHash, runRelevantHash) {
			return true, recoveredKey
		}
	}
	recoveredKey.Zero()
	return false, recoveredKey
}

func GetHashMembership(hashes [][32]byte, relevantHash [32]byte) bool {
	for _, hash := range hashes {
		if CheckHashesEqual(hash, relevantHash) {
			return true
		}
	}
	return false
}

func GetSaltedKeyMembership(hashes [][32]byte, salt [32]byte,
	k kyber.Scalar) bool {
	bytesKey := ConvertKeyToBytes(k)
	saltedHash := GetSaltedHash(salt, bytesKey)
	return GetHashMembership(hashes, saltedHash)
}

func CheckSubsecretAlreadyRecovered(obtainedSecrets []kyber.Scalar,
	recovered kyber.Scalar) bool {
	for _, obtainedSecret := range obtainedSecrets {
		if obtainedSecret.Equal(recovered) {
			return true
		}
	}
	return false
}

func CheckShareAlreadyUsed(usedShares []*share.PriShare,
	shareVal *share.PriShare) bool {
	for _, usedShare := range usedShares {
		if usedShare.I == shareVal.I && (usedShare.V).Equal(shareVal.V) {
			return true
		}
	}
	return false
}

// Given two sets of shares,
// Find the difference between the two sets
func GetSharesSetDifference(shares1, shares2 []*share.PriShare) ([]*share.PriShare,
	error) {
	var outputShares []*share.PriShare
	for _, share1 := range shares1 {
		inFlag := false
		for _, share2 := range shares2 {
			if CheckValuesEqual(share1.V, share2.V) {
				if share1.I == share2.I {
					inFlag = true
					break
				}
			}
		}
		if !inFlag {
			outputShares = append(outputShares, share1)
		}
	}
	return outputShares, nil
}
