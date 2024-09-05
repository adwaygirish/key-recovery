package secret_binary_extension

import (
	"encoding/binary"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"

	"crypto/rand"
	"key_recovery/modules/errors"
	"log"
)

var recoveryHint = uint16(0)

type HintedTPacket struct {
	Nonce               [32]byte            // includes the list of salts used for each share
	RelevantEncryptions [][][]byte          // includes the list of h(salt || parent secret)
	ShareData           [][]shamir.PriShare // share data (for now only one share)
}

// This function generates thresholded shares of the secret
func GenerateHintedTTwoLayeredOptIndisShares(f shamir.Field, n int,
	secretKey [][]uint16, absoluteThreshold int,
	noOfSubsecrets, percentageLeavesLayerThreshold int) ([][][]uint16,
	[][]shamir.PriShare, map[int]map[uint16][]uint16, []uint16, error) {
	// Shares which are to be distributed among the trustees
	var leavesData [][]shamir.PriShare
	var subsecrets [][][]uint16
	var xUsedCoords []uint16
	parentSubsecrets := make(map[int]map[uint16][]uint16)

	// If the percentage threshold is greater than 100, then it does not make
	// sense to run the recovery
	if percentageLeavesLayerThreshold > 100 {
		return nil, nil, nil, nil, errors.ErrInvalidThreshold
	}
	// 0 is used for the key itself
	xUsedCoords = append(xUsedCoords, 0)
	leavesNumbers := utils.GenerateAdditiveTwoLayeredTree(
		n, percentageLeavesLayerThreshold, absoluteThreshold, noOfSubsecrets)

	// Generate the shares for all the layers except the leaves layer
	GenerateHintedTIndisUpperLayers(f, secretKey, noOfSubsecrets,
		&subsecrets)
	// Generate the shares for the leaves layer
	GenerateHintedTIndisLeavesLayer(f, absoluteThreshold,
		leavesNumbers, subsecrets, &leavesData, &xUsedCoords,
		parentSubsecrets)

	return subsecrets, leavesData, parentSubsecrets, xUsedCoords, nil
}

// This function is called by the GenerateAdditiveTwoLayeredOptIndisShares
// for generating shares of the layers above the leaves
// Simply generates (n-1) random points and then, generates the point which is
// secret key minus the sum of the (n-1) points
func GenerateHintedTIndisUpperLayers(f shamir.Field, secretKey [][]uint16,
	noOfSubsecrets int, subsecrets *[][][]uint16) {
	buf := make([]byte, 2)
	for ind, keyPart := range secretKey {
		sharesSums := make([]uint16, len(secretKey[ind]))
		(*subsecrets) = append((*subsecrets), [][]uint16{})
		// The first (n - 1) shares are generated randomly
		for i := 0; i < noOfSubsecrets-1; i++ {
			(*subsecrets)[ind] = append((*subsecrets)[ind], []uint16{})
			for j := 0; j < len(secretKey[ind]); j++ {
				if _, err := rand.Read(buf); err != nil {
					log.Fatalln(err)
				}
				shareVal := binary.BigEndian.Uint16(buf)
				(*subsecrets)[ind][i] = append((*subsecrets)[ind][i], shareVal)
				sharesSums[j] = shamir.Add(sharesSums[j], shareVal)
			}
		}
		// The last share is the XOR of rest of the shares with the
		// secret key
		(*subsecrets)[ind] = append((*subsecrets)[ind], []uint16{})
		for j := 0; j < len(secretKey[0]); j++ {
			lastShare := shamir.Add(sharesSums[j], keyPart[j])
			(*subsecrets)[ind][noOfSubsecrets-1] = append((*subsecrets)[ind][noOfSubsecrets-1],
				lastShare)
		}
	}
}

func GenerateHintedTIndisLeavesLayer(f shamir.Field,
	absoluteThreshold int,
	leavesNumbers []int, subsecrets [][][]uint16,
	leavesData *[][]shamir.PriShare, xUsedCoords *[]uint16,
	parentSubsecrets map[int]map[uint16][]uint16) {
	for partIndex, subsecretPart := range subsecrets {
		*leavesData = append(*leavesData, []shamir.PriShare{})
		parentSubsecrets[partIndex] = make(map[uint16][]uint16)
		for subsecretIndex, sharesNumber := range leavesNumbers {
			subsecretVal := subsecretPart[subsecretIndex]
			shareVals, err := GenerateRandomXShares(f, absoluteThreshold,
				sharesNumber, subsecretVal, xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			(*leavesData)[partIndex] = append((*leavesData)[partIndex],
				shareVals...)
			for _, shareVal := range shareVals {
				parentSubsecrets[partIndex][shareVal.X] = subsecretVal
			}
		}
	}
}

// The packet generation does not require any x-coordinates
// Therefore, there is no need to store any kind of marker info
// Storing only two salted hash works for our system
func GetHintedTSharePackets(f shamir.Field,
	secretKey [][]uint16,
	trustees, absoluteThreshold int,
	leavesData [][]shamir.PriShare, subsecrets [][][]uint16,
	parentSubsecrets map[int]map[uint16][]uint16,
	xUsedCoords *[]uint16, noOfHints int) ([]HintedTPacket, int, int, error) {
	if absoluteThreshold > trustees {
		return nil, -1, -1, errors.ErrInvalidThreshold
	}
	var encryptionLength int
	var anonymitySharePackets []HintedTPacket
	totalShares := len(leavesData[0])
	sharesPerPerson := totalShares / trustees
	// Get how many shares each person should get
	personWiseShareDistribution, maxSharesPerPerson :=
		utils.GetPersonWiseShareNumber(trustees,
			totalShares, sharesPerPerson)
	// Get the trustees who should be hinted
	trusteesNums := utils.GenerateIndicesSet(trustees)
	utils.Shuffle(trusteesNums)
	var hintedTrustees []uint16
	for i := 0; i < noOfHints; i++ {
		hintedTrustees = append(hintedTrustees, uint16(trusteesNums[i]))
	}

	// Indices of the leaves
	allLeavesIndices := make([][]int, 0)
	for i := 0; i < len(secretKey); i++ {
		// Indices of the leaves
		leavesIndices := utils.GenerateIndicesSet(totalShares)
		// Randomize the leaves that the trustees should receive
		utils.Shuffle(leavesIndices)
		allLeavesIndices = append(allLeavesIndices, leavesIndices)
	}
	currentIndices := make([]int, len(secretKey))
	for i := 0; i < trustees; i++ {
		var hPacket HintedTPacket
		noOfSharesReceived := personWiseShareDistribution[i]
		nonce, _ := crypto_protocols.GenerateSalt32()
		hPacket.Nonce = nonce
		el, err := GenerateHintedTPerPersonSharePackets(noOfSharesReceived,
			allLeavesIndices, leavesData, &currentIndices, secretKey,
			parentSubsecrets, &hPacket, hintedTrustees, uint16(i))
		if err != nil {
			return nil, -1, -1, err
		}
		encryptionLength = el
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateHintedTRandomPackets(noOfPackets, len(secretKey[0]),
				len(secretKey), &hPacket, xUsedCoords, encryptionLength)
		}
		anonymitySharePackets = append(anonymitySharePackets, hPacket)
	}
	return anonymitySharePackets, maxSharesPerPerson, encryptionLength, nil
}

func GenerateHintedTPerPersonSharePackets(noOfSharesReceived int,
	allLeavesIndices [][]int, leavesData [][]shamir.PriShare,
	currentIndices *[]int,
	secretKey [][]uint16, parentSubsecrets map[int]map[uint16][]uint16,
	hPacket *HintedTPacket, hintedTrustees []uint16, ownIndex uint16) (int, error) {
	var encryptionLength int
	buf := make([]byte, 2)
	for ind, keyPart := range secretKey {
		// Firstly, add the encryption for that part of the key
		(*hPacket).RelevantEncryptions = append((*hPacket).RelevantEncryptions, [][]byte{})
		(*hPacket).ShareData = append((*hPacket).ShareData, []shamir.PriShare{})
		noncedEncSecretKey, el, err := crypto_protocols.GetHintedRelevantEncryptionBinExt((*hPacket).Nonce, keyPart, recoveryHint)
		if err != nil {
			return -1, err
		}
		(*hPacket).RelevantEncryptions[ind] = append((*hPacket).RelevantEncryptions[ind],
			noncedEncSecretKey)
		encryptionLength = el
		// Generate a random integer in the range [0, max)
		_, err = rand.Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		hint := (binary.BigEndian.Uint16(buf)) % uint16(len(hintedTrustees))
		if hint == ownIndex {
			hint = (hint + uint16(1)) % uint16(len(hintedTrustees))
		}
		for j := 0; j < noOfSharesReceived; j++ {
			leafShareVal := leavesData[ind][allLeavesIndices[ind][(*currentIndices)[ind]]]
			parentSubsecret := parentSubsecrets[ind][leafShareVal.X]

			noncedEncryption, _, err := crypto_protocols.GetHintedRelevantEncryptionBinExt((*hPacket).Nonce, parentSubsecret, hint+uint16(1))
			if err != nil {
				log.Fatal(err)
				return -1, err
			}
			// If the share of the same subsecrets are being stored
			// then do not store the hash twice
			// To keep the packets indistinguishable, store some random blobs
			// inside the packets
			if !crypto_protocols.GetEncryptionMembership((*hPacket).RelevantEncryptions[ind], noncedEncryption) {
				(*hPacket).RelevantEncryptions[ind] = append((*hPacket).RelevantEncryptions[ind], noncedEncryption)
			} else {
				randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
				if err != nil {
					log.Fatalln("Error in generating random packets")
				}
				(*hPacket).RelevantEncryptions[ind] = append((*hPacket).RelevantEncryptions[ind],
					randomBytes)
			}
			(*hPacket).ShareData[ind] = append((*hPacket).ShareData[ind], leafShareVal)
			(*currentIndices)[ind] += 1
		}

	}
	return encryptionLength, nil
}

func GenerateHintedTRandomPackets(noOfPackets, relevantSize, keySize int,
	hPacket *HintedTPacket, xUsedCoords *[]uint16, encryptionLength int) {
	bufX := make([]byte, 2)
	bufY := make([]byte, 2*relevantSize)
	for i := 0; i < keySize; i++ {
		// This check is necessary to differentiate between a packet
		// distributed among trustees and non-trustees
		if len((*hPacket).ShareData) != keySize {
			(*hPacket).ShareData = append((*hPacket).ShareData, []shamir.PriShare{})
			(*hPacket).RelevantEncryptions = append((*hPacket).RelevantEncryptions, [][]byte{})
		}
		for j := 0; j < (noOfPackets); j++ {
			if _, err := rand.Read(bufX); err != nil {
				log.Fatalln(err)
			}
			x := binary.BigEndian.Uint16(bufX)
			// We cannot use a zero x coordinate otherwise the y values
			// would be the intercepts i.e. the secret value itself.
			if x == 0 {
				continue
			}
			// Check if the x-coordinate has been already used
			exists := utils.IsInSliceUint16((*xUsedCoords), x)
			// If the x-coordinate repeats, do not store it again
			if exists {
				continue
			}
			if _, err := rand.Read(bufY); err != nil {
				log.Fatalln(err)
			}
			y := shamir.BytesToUint16s(bufY)
			randShareVal := shamir.PriShare{X: x, Y: y}
			(*xUsedCoords) = append((*xUsedCoords), x)
			(*hPacket).ShareData[i] = append((*hPacket).ShareData[i], randShareVal)
			randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			(*hPacket).RelevantEncryptions[i] = append((*hPacket).RelevantEncryptions[i],
				randomBytes)
			j++
		}
	}
}

func GetHintedTAnonymityPackets(sharePackets []HintedTPacket,
	anonymitySetSize, maxSharesPerPerson, relevantSize, keySize int,
	xUsedCoords *[]uint16, encryptionLength int) ([]HintedTPacket, error) {
	var anonymityPackets []HintedTPacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var hPacket HintedTPacket
		nonce, _ := crypto_protocols.GenerateSalt32()
		hPacket.Nonce = nonce
		GenerateHintedTRandomPackets(maxSharesPerPerson,
			relevantSize, keySize, &hPacket, xUsedCoords, encryptionLength)
		// Store an encryption that would be similar to the encryption of the
		// secret key
		// This is to ensure that the number of encryptions remains the same
		// in share packets and anonymity packets
		// Store an encryption that would be similar to the encryption of the
		// secret key
		// This is to ensure that the number of encryptions remains the same
		// in share packets and anonymity packets
		for j := 0; j < keySize; j++ {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			(hPacket).RelevantEncryptions[j] = append((hPacket).RelevantEncryptions[j],
				randomBytes)
		}

		anonymityPackets = append(anonymityPackets, hPacket)
	}
	return anonymityPackets, nil
}
