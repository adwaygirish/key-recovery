package crypto

import (
	"crypto/subtle"
	"encoding/binary"
	"key_recovery/modules/shamir"
	"log"
)

func CompareUint16s(data1, data2 []uint16) bool {
	data1Bytes := shamir.Uint16sToBytes(data1)
	data2Bytes := shamir.Uint16sToBytes(data2)
	return subtle.ConstantTimeCompare(data1Bytes, data2Bytes) == 1
}

func GetAdditiveIndisShareMatchBinExt(recovered []uint16,
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte) (bool, [32]byte, error) {
	var correctHash [32]byte
	bytesVal := shamir.Uint16sToBytes(recovered)
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

func CheckShareAlreadyUsedBinExt(usedShares []shamir.PriShare,
	shareVal shamir.PriShare) bool {
	for _, usedShare := range usedShares {
		if usedShare.X == shareVal.X && CompareUint16s(shareVal.Y, usedShare.Y) {
			return true
		}
	}
	return false
}

func CheckSubsecretAlreadyRecoveredBinExt(obtainedSecrets [][]uint16,
	recovered []uint16) bool {
	for _, obtainedSecret := range obtainedSecrets {
		if CompareUint16s(recovered, obtainedSecret) {
			return true
		}
	}
	return false
}

// Given two sets of shares,
// Find the difference between the two sets
func GetSharesSetDifferenceBinExt(shares1,
	shares2 []shamir.PriShare) ([]shamir.PriShare, error) {
	var outputShares []shamir.PriShare
	for _, share1 := range shares1 {
		inFlag := false
		for _, share2 := range shares2 {
			if CompareUint16s(share1.Y, share2.Y) && share1.X == share2.X {
				inFlag = true
				break
			}
		}
		if !inFlag {
			outputShares = append(outputShares, share1)
		}
	}
	return outputShares, nil
}

func GetAdditiveSaltedHashMatchBinExt(
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte,
	obtainedSubsecrets [][]uint16) (bool, []uint16) {
	recoveredKey := make([]uint16, len(obtainedSubsecrets[0]))
	for _, obtainedSubsecret := range obtainedSubsecrets {
		tempKey, err := shamir.SliceAdd(recoveredKey, obtainedSubsecret)
		if err != nil {
			log.Fatalln(err)
		}
		recoveredKey = tempKey
	}
	obtainedKeyBytes := shamir.Uint16sToBytes(recoveredKey)
	saltedHash := GetSaltedHash(runRelevantSalt, obtainedKeyBytes)
	for _, runRelevantHash := range runRelevantHashes {
		if CheckHashesEqual(saltedHash, runRelevantHash) {
			return true, recoveredKey
		}
	}
	return false, recoveredKey
}

func GetSaltedKeyMembershipBinExt(hashes [][32]byte, salt [32]byte,
	k []uint16) bool {
	bytesKey := shamir.Uint16sToBytes(k)
	saltedHash := GetSaltedHash(salt, bytesKey)
	return GetHashMembership(hashes, saltedHash)
}

func CheckRecSecretKeyBinExt(
	baseHash [32]byte,
	k []uint16) bool {
	obtainedKeyBytes := shamir.Uint16sToBytes(k)
	obtainedKeyHash := GetSHA256(obtainedKeyBytes)
	return CheckHashesEqual(baseHash, obtainedKeyHash)
}

// **************************************************************************
// **************************************************************************

// *************Relevant functions for thresholded packets*******************
// **************************************************************************

func GetRelevantEncryptionBinExt(nonce [32]byte,
	shareVal shamir.PriShare) ([]byte, int, error) {
	// Padding to be added in the marker info to show that the
	// the obtained secret is correct
	zeroPadding := [8]byte{}
	// The padding for the secret key is different from the others
	bytesIndex := shamir.ConvertIndexUint16ToBytes(shareVal.X)
	// Format of the markerData
	// nonce || 00000000 || index || indicator bytes
	var markerData []byte
	// First of all, append the salt
	for _, nonceData := range nonce {
		markerData = append(markerData, nonceData)
	}
	// Next, append the zero padding
	for _, zero := range zeroPadding {
		markerData = append(markerData, zero)
	}
	// Then, append the index of the share
	markerData = append(markerData, bytesIndex...)
	encryptionKey := shamir.Uint16sToBytes(shareVal.Y)
	// Encrypt the marker information generated
	encryption := GetAESEncryption(encryptionKey, markerData)
	// Encryption length represents the length for a certain share
	encryptionLength := len(encryption)
	return encryption, encryptionLength, nil
}

func GetThresholdedIndisShareMatchBinExt(recovered []uint16,
	runRelevantNonce [32]byte,
	runRelevantEncryptions [][]byte) (bool, uint16, []byte, error) {
	var correctEncryption []byte
	bytesVal := shamir.Uint16sToBytes(recovered)
	correctX, correctEncryption, markerMatched, err := ThresholdedDecryptionCheckBinExt(bytesVal,
		runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		return false, 0, nil, err
	}
	return markerMatched, correctX, correctEncryption, nil
}

func ThresholdedDecryptionCheckBinExt(
	bytesVal []byte,
	nonce [32]byte,
	runRelevantEncryptions [][]byte) (uint16, []byte, bool, error) {
	// fmt.Println("zz", len(runRelevantMarkerInfo))
	for _, relevantEncryption := range runRelevantEncryptions {
		copiedEncryption := make([]byte, len(relevantEncryption))
		copy(copiedEncryption, relevantEncryption)
		encryptionMatched := true
		plaintext, validity, err := GetAESDecryption(bytesVal, copiedEncryption)
		if err != nil {
			return 0, nil, false, err
		}
		if !validity {
			return 0, nil, false, err
		}
		// The structure of the marker info is
		// nonce || 00000000 || index
		// Thus, first check if the first 32 bytes contain the salt
		for i := 0; i < 32; i++ {
			if plaintext[i] != nonce[i] {
				encryptionMatched = false
				break
			}
		}
		// If there is no match, then continue to the next marker info
		if !encryptionMatched {
			continue
		}
		// fmt.Println("Passed 1")
		// Then, check if the next 8 bytes are 0 or not
		for i := 32; i < 40; i++ {
			if plaintext[i] != 0 {
				encryptionMatched = false
				break
			}
		}
		// If there is no match, then continue to the next marker info
		if !encryptionMatched {
			continue
		}
		// The next 8 bytes indicate the x index of the share
		byteXValue := plaintext[40:42]
		xIndex := binary.BigEndian.Uint16(byteXValue)
		return xIndex, relevantEncryption, encryptionMatched, nil

	}
	return 0, nil, false, nil
}

func GetThresholdedNoncedSubsecretMatchBinExt(
	f shamir.Field,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets []shamir.PriShare) (bool, []uint16) {
	recoveredKey, err := f.CombineUniqueX(obtainedSubsecrets)
	if err != nil {
		log.Fatal(err)
		return false, nil
	}
	bytesVal := shamir.Uint16sToBytes(recoveredKey)
	correctX, _, markerMatched, err := ThresholdedDecryptionCheckBinExt(bytesVal,
		runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatal(err)
		return false, nil
	}
	if (markerMatched) && (correctX == 0) {
		return true, recoveredKey
	}
	return false, nil
}

// **************************************************************************
// **************************************************************************

// ***************Relevant functions for hinted packets**********************
// **************************************************************************
func GetHintedRelevantEncryptionBinExt(nonce [32]byte,
	subsecret []uint16, hint uint16) ([]byte, int, error) {
	// Padding to be added in the marker info to show that the
	// the obtained secret is correct
	zeroPadding := [8]byte{}
	// The padding for the secret key is different from the others
	bytesHint := shamir.ConvertIndexUint16ToBytes(hint)
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
	encryptionKey := shamir.Uint16sToBytes(subsecret)
	// Encrypt the marker information generated
	encryption := GetAESEncryption(encryptionKey, markerData)
	// Encryption length represents the length for a certain share
	encryptionLength := len(encryption)
	return encryption, encryptionLength, nil
}

func GetHintedTNoncedSubsecretMatchBinExt(
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets [][]uint16,
	recoveryHint uint16) (bool, []uint16) {
	recoveredKey := make([]uint16, len(obtainedSubsecrets[0]))
	for _, obtainedSubsecret := range obtainedSubsecrets {
		tempKey, err := shamir.SliceAdd(recoveredKey, obtainedSubsecret)
		if err != nil {
			log.Fatalln(err)
		}
		recoveredKey = tempKey
	}
	bytesVal := shamir.Uint16sToBytes(recoveredKey)
	correctX, _, markerMatched, err := ThresholdedDecryptionCheckBinExt(bytesVal,
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
