package crypto

import (
	"crypto/cipher"
	"fmt"
	"key_recovery/modules/errors"
	"log"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// **************************************************************************
// **************************************************************************

// *************Relevant functions for thresholded packets*******************
// **************************************************************************

func GetRelevantEncryption(nonce [32]byte,
	shareVal *share.PriShare) ([]byte, int, error) {
	// Padding to be added in the marker info to show that the
	// the obtained secret is correct
	zeroPadding := [8]byte{}
	// The padding for the secret key is different from the others
	bytesIndex := ConvertIndexToBytes(shareVal.I)
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
	encryptionKey := ConvertKeyToBytes(shareVal.V)
	// Encrypt the marker information generated
	encryption := GetAESEncryption(encryptionKey, markerData)
	// Encryption length represents the length for a certain share
	encryptionLength := len(encryption)
	return encryption, encryptionLength, nil
}

func ThresholdedDecryptionCheck(
	bytesVal []byte,
	nonce [32]byte,
	runRelevantEncryptions [][]byte) (int, []byte, bool, error) {
	// fmt.Println("zz", len(runRelevantMarkerInfo))
	for _, relevantEncryption := range runRelevantEncryptions {
		copiedEncryption := make([]byte, len(relevantEncryption))
		copy(copiedEncryption, relevantEncryption)
		encryptionMatched := true
		plaintext, validity, err := GetAESDecryption(bytesVal, copiedEncryption)
		if err != nil {
			return -1, nil, false, err
		}
		if !validity {
			return -1, nil, false, err
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
		byteXValue := plaintext[40:48]
		xIndex := ConvertBytesToIndex(byteXValue)
		return xIndex, relevantEncryption, encryptionMatched, nil

	}
	return -1, nil, false, nil
}

func GetThresholdedIndisShareMatch(recovered kyber.Scalar,
	runRelevantNonce [32]byte,
	runRelevantEncryptions [][]byte) (bool, int, []byte, error) {
	var correctEncryption []byte
	bytesVal := ConvertKeyToBytes(recovered)
	correctX, correctEncryption, markerMatched, err := ThresholdedDecryptionCheck(bytesVal,
		runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		return false, -1, nil, err
	}
	return markerMatched, correctX, correctEncryption, nil
}

func GetThresholdedNoncedSubsecretMatch(g kyber.Group, randSeedShares cipher.Stream,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets []*share.PriShare) (bool, kyber.Scalar) {
	recoveredKey, err := share.RecoverSecret(g, obtainedSubsecrets,
		len(obtainedSubsecrets), len(obtainedSubsecrets))
	if err != nil {
		log.Fatal(err)
		return false, nil
	}
	bytesVal := ConvertKeyToBytes(recoveredKey)
	correctX, _, markerMatched, err := ThresholdedDecryptionCheck(bytesVal,
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

func GetEncryptionMembership(relevantEncryptions [][]byte,
	noncedEncryption []byte) bool {
	for _, encryption := range relevantEncryptions {
		if CheckByteArrayEqual(encryption, noncedEncryption) {
			return true
		}
	}
	return false
}

func CombineNonces(slices [][32]byte) [32]byte {
	var result [32]byte
	for _, slice := range slices {
		for i := 0; i < 32; i++ {
			result[i] ^= slice[i]
		}
	}
	return result
}

// **************************************************************************
// **************************************************************************

// **************Relevant functions for anonymity packets********************
// **************************************************************************

func GetAnonymityMarkerInfo(
	encryptionLength int,
	blobsNumber int) ([][]byte,
	error) {
	var output [][]byte
	for i := 0; i < blobsNumber; i++ {
		randomEncryption, err := GenerateRandomBytes(encryptionLength)
		if err != nil {
			return nil, err
		} else {
			output = append(output, randomEncryption)
		}
	}
	return output, nil
}

// Function for generating marke information for share packets
func GetMarkerInfo(
	secretKey kyber.Scalar,
	relevantSecrets [][]*share.PriShare,
	salt [32]byte,
	shareVals []*share.PriShare,
	noOfSharesReceived int,
	noOfLevels int) ([][]byte, int, error) {
	// Padding to be added in the marker info to show that the
	// the obtained secret is correct
	zeroPadding := [8]byte{}
	var output [][]byte
	// The encryption length is relevant in generating random information for
	// the share packets which do not have shares and it also helps in
	// generating the packets for anonymity set
	var encryptionLength int
	// Generate the marker info for each share
	for i := 0; i < noOfSharesReceived; i++ {
		for j, relevantSecret := range relevantSecrets[i] {
			// The padding for the secret key is different from the others
			bytesIndex := ConvertIndexToBytes(relevantSecret.I)
			// Format of the markerData
			// salt || 00000000 || index || indicator bytes
			var markerData []byte
			// First of all, append the salt
			for _, saltData := range salt {
				markerData = append(markerData, saltData)
			}
			// Next, append the zero padding
			for _, zero := range zeroPadding {
				markerData = append(markerData, zero)
			}
			// Then, append the index of the share
			markerData = append(markerData, bytesIndex...)
			// When you have the secret key, then pad more zeros
			if j == len(relevantSecrets[i])-1 {
				// Check if the secret key actually matches
				valuesEqual := CheckValuesEqual(secretKey, relevantSecret.V)
				if !valuesEqual {
					return nil, -1, errors.ErrBytesNotEqual
				}
				for _, zero := range zeroPadding {
					markerData = append(markerData, zero)
				}
			} else {
				// Otherwise pad some random bits
				randomBytes, err := GenerateRandomBytes(8)
				if err != nil {
					return nil, -1, err
				}
				markerData = append(markerData, randomBytes...)
			}
			encryptionKey := ConvertKeyToBytes(relevantSecret.V)
			// Encrypt the marker information generated
			encryption := GetAESEncryption(encryptionKey, markerData)
			// Encryption length represents the length for a certain share
			encryptionLength = len(encryption)
			output = append(output, encryption)
		}
	}
	// For the random blobs, just add some random data to the list
	// shareVals contains both shares and random (x, y) coordinates
	for i := 0; i < len(shareVals)-noOfSharesReceived; i++ {
		// Generate random blobs for each layer
		for j := 0; j < noOfLevels; j++ {
			randomEncryption, err := GenerateRandomBytes(encryptionLength)
			if err != nil {
				return nil, -1, err
			} else {
				output = append(output, randomEncryption)
			}
		}
	}
	return output, encryptionLength, nil
}

func GetIndisShareMatch(
	recovered kyber.Scalar,
	runRelevantHashes [][32]byte,
	runRelevantMarkerInfo [][]byte,
	runRelevantSalt [32]byte) (bool, bool, [32]byte, []byte, int, bool, error) {
	var correctHash [32]byte
	var correctMarkerInfo []byte
	var correctX int
	var finalLevelObtained bool
	var markerMatched bool
	var err error
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
	if isContainedHash {
		// fmt.Println("Here")
		correctX, finalLevelObtained, correctMarkerInfo, markerMatched, err = CorrectDecryptionCheck(bytesVal,
			runRelevantSalt, runRelevantMarkerInfo)
		// fmt.Println(correctX)
		if err != nil {
			return true, false, correctHash, nil, -1, false, err
		}
	}

	return (isContainedHash), (markerMatched), correctHash, correctMarkerInfo, correctX, finalLevelObtained, nil
}

func CorrectDecryptionCheck(
	bytesVal []byte,
	salt [32]byte,
	runRelevantMarkerInfo [][]byte) (int, bool, []byte, bool, error) {
	// fmt.Println("zz", len(runRelevantMarkerInfo))
	for _, markerInfo := range runRelevantMarkerInfo {
		// fmt.Println("hehe", markerInfo)
		// fmt.Println("aa")
		copiedMarkerInfo := make([]byte, len(markerInfo))
		copy(copiedMarkerInfo, markerInfo)
		markerMatched := true
		plaintext, validity, err := GetAESDecryption(bytesVal, copiedMarkerInfo)
		fmt.Println(plaintext)
		if err != nil {
			// fmt.Println("yy")
			return -1, false, nil, false, err
		}
		if !validity {
			// fmt.Println("xx")
			return -1, false, nil, false, err
		}
		// The structure of the marker info is
		// salt || 00000000 || index || indicator bytes
		// Thus, first check if the first 32 bytes contain the salt
		for i := 0; i < 32; i++ {
			if plaintext[i] != salt[i] {
				markerMatched = false
				break
			}
		}
		// If there is no match, then continue to the next marker info
		if !markerMatched {
			continue
		}
		// fmt.Println("Passed 1")
		// Then, check if the next 8 bytes are 0 or not
		for i := 32; i < 40; i++ {
			if plaintext[i] != 0 {
				markerMatched = false
				break
			}
		}
		// If there is no match, then continue to the next marker info
		if !markerMatched {
			continue
		}
		// The next 8 bytes indicate the x index of the share
		byteXValue := plaintext[40:48]
		xIndex := ConvertBytesToIndex(byteXValue)
		// Final check the indicator bytes
		// These bytes indicate if the recovered secret is the main secret
		// If all the bytes of the indicator are 0's,
		// then the secret has been recovered
		padCheckBytes := plaintext[48:]
		finalLevelObtained := true
		for _, padCheckByte := range padCheckBytes {
			if padCheckByte != 0 {
				finalLevelObtained = false
				break
			}
		}
		return xIndex, finalLevelObtained, markerInfo, markerMatched, nil

	}
	return -1, false, nil, false, errors.ErrMarkerNoMatch
}

func CheckSharePresent(
	shareList []*share.PriShare,
	shareVal *share.PriShare) bool {
	for _, s := range shareList {
		if s.I == shareVal.I && CheckValuesEqual(s.V, shareVal.V) {
			return true
		}
	}
	return false
}
