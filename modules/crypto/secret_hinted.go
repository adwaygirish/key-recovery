package crypto

import (
	"crypto/cipher"
	"log"

	"go.dedis.ch/kyber/v3"
)

// **************************************************************************
// **************************************************************************

// **************Relevant functions for hinted packets***********************
// **************************************************************************

func GetHintedRelevantEncryption(nonce [32]byte,
	subsecret kyber.Scalar, hint int) ([]byte, int, error) {
	// Padding to be added in the marker info to show that the
	// the obtained secret is correct
	zeroPadding := [8]byte{}
	// The padding for the secret key is different from the others
	bytesHint := ConvertIndexToBytes(hint)
	// Format of the markerData
	// nonce || 00000000 || hint
	var markerData []byte
	// First of all, append the nonce
	for _, nonceData := range nonce {
		markerData = append(markerData, nonceData)
	}
	// Next, append the zero padding
	for _, zero := range zeroPadding {
		markerData = append(markerData, zero)
	}
	// Then, append the index of the share
	markerData = append(markerData, bytesHint...)
	encryptionKey := ConvertKeyToBytes(subsecret)
	// Encrypt the marker information generated
	encryption := GetAESEncryption(encryptionKey, markerData)
	// Encryption length represents the length for a certain share
	encryptionLength := len(encryption)
	return encryption, encryptionLength, nil
}

func CheckHintTAlreadyUsed(hints []int,
	hint int) bool {
	for _, h := range hints {
		if hint == h {
			return true
		}
	}
	return false
}

func GetHintedTNoncedSubsecretMatch(g kyber.Group, randSeedShares cipher.Stream,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets []kyber.Scalar,
	recoveryHint int) (bool, kyber.Scalar) {
	recoveredKey := g.Scalar().Pick(randSeedShares)
	recoveredKey = recoveredKey.Set(obtainedSubsecrets[0])
	for _, obtainedSubsecret := range obtainedSubsecrets[1:] {
		recoveredKey = recoveredKey.Add(recoveredKey, obtainedSubsecret)
	}
	bytesVal := ConvertKeyToBytes(recoveredKey)
	correctX, _, markerMatched, err := ThresholdedDecryptionCheck(bytesVal,
		runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatal(err)
		return false, nil
	}
	if (markerMatched) && (correctX == recoveryHint) {
		return true, recoveredKey
	}
	return false, nil
}
