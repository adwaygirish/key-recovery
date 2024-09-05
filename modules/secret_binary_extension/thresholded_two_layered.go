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

// In this version of the thresholded packet,
// we need to store encryptions and a hash because of the following reasons:
// 1. Encryptions for indicating the recovery of the subsecrets
// and for representing the recovery of various parts of the secret
// 2. Hash for indicating the recovery of the final secret
// We need this extra data because the secret can be of any size and AES
// supports key size of 128, 192 and 256
// Therefore, we have to break secrets into smaller chunks
type ThresholdedPacket struct {
	Nonce               [32]byte            // includes the list of salts used for each share
	RelevantEncryptions [][][]byte          // includes the list of h(salt || parent secret)
	ShareData           [][]shamir.PriShare // share data (for now only one share)
}

// This function generates thresholded shares of the secret
func GenerateThresholdedTwoLayeredOptIndisShares(f shamir.Field, n int,
	secretKey [][]uint16, absoluteThreshold int,
	noOfSubsecrets int, percentageLeavesLayerThreshold,
	percentageUpperLayerThreshold int) ([][]shamir.PriShare, [][]shamir.PriShare,
	map[int]map[uint16]shamir.PriShare, []uint16, error) {
	// Shares which are to be distributed among the trustees
	var leavesData [][]shamir.PriShare
	var subsecrets [][]shamir.PriShare
	var xUsedCoords []uint16
	parentSubsecrets := make(map[int]map[uint16]shamir.PriShare)

	// If the percentage threshold is greater than 100, then it does not make
	// sense to run the recovery
	if percentageLeavesLayerThreshold > 100 {
		return nil, nil, nil, nil, errors.ErrInvalidThreshold
	}
	// 0 is used for the key itself
	xUsedCoords = append(xUsedCoords, 0)
	layerwiseThresholds, _, leavesNumbers := utils.GenerateTwoLayeredTree(n,
		percentageLeavesLayerThreshold, absoluteThreshold,
		percentageUpperLayerThreshold, noOfSubsecrets)

	// Generate the shares for all the layers except the leaves layer
	GenerateThresholdedIndisUpperLayers(f, secretKey, noOfSubsecrets,
		layerwiseThresholds[0], &subsecrets, &xUsedCoords)
	// Generate the shares for the leaves layer
	GenerateThresholdedIndisLeavesLayer(f, absoluteThreshold,
		leavesNumbers, subsecrets, &leavesData, &xUsedCoords,
		parentSubsecrets)

	return subsecrets, leavesData, parentSubsecrets, xUsedCoords, nil
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the layers above the leaves
func GenerateThresholdedIndisUpperLayers(f shamir.Field, secretKey [][]uint16,
	noOfSubsecrets int, subsecretsThreshold int,
	subsecrets *[][]shamir.PriShare, xUsedCoords *[]uint16) {
	// Generate Shamir's secret shares for the main secret
	for ind, keyPart := range secretKey {
		shareVals, err := GenerateRandomXShares(f, subsecretsThreshold,
			noOfSubsecrets, keyPart, xUsedCoords)
		if err != nil {
			log.Fatalln(err)
		}
		(*subsecrets) = append((*subsecrets), []shamir.PriShare{})
		(*subsecrets)[ind] = append((*subsecrets)[ind], shareVals...)
	}
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the leaves layer
// Leaves are distribute among the trustees
func GenerateThresholdedIndisLeavesLayer(f shamir.Field,
	absoluteThreshold int,
	leavesNumbers []int, subsecrets [][]shamir.PriShare,
	leavesData *[][]shamir.PriShare, xUsedCoords *[]uint16,
	parentSubsecrets map[int]map[uint16]shamir.PriShare) {
	for partIndex, subsecretPart := range subsecrets {
		*leavesData = append(*leavesData, []shamir.PriShare{})
		parentSubsecrets[partIndex] = make(map[uint16]shamir.PriShare)
		for subsecretIndex, sharesNumber := range leavesNumbers {
			subsecretVal := subsecretPart[subsecretIndex]
			shareVals, err := GenerateRandomXShares(f, absoluteThreshold,
				sharesNumber, subsecretVal.Y, xUsedCoords)
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

func GetThresholdedSharePackets(f shamir.Field, secretKey [][]uint16,
	trustees, absoluteThreshold int,
	leavesData [][]shamir.PriShare, subsecrets [][]shamir.PriShare,
	parentSubsecrets map[int]map[uint16]shamir.PriShare,
	xUsedCoords *[]uint16) ([]ThresholdedPacket, int, int, error) {
	if absoluteThreshold > trustees {
		return nil, -1, -1, errors.ErrInvalidThreshold
	}
	var sharePackets []ThresholdedPacket
	encryptionLength := 0
	totalShares := len(leavesData[0])
	sharesPerPerson := totalShares / trustees
	// Get how many shares each person should get
	personWiseShareDistribution, maxSharesPerPerson :=
		utils.GetPersonWiseShareNumber(trustees,
			totalShares, sharesPerPerson)
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
		var thPacket ThresholdedPacket
		noOfSharesReceived := personWiseShareDistribution[i]
		nonce, _ := crypto_protocols.GenerateSalt32()
		thPacket.Nonce = nonce
		el, err := GenerateThresholdedPerPersonSharePackets(noOfSharesReceived,
			allLeavesIndices, leavesData, &currentIndices, secretKey,
			parentSubsecrets, &thPacket)
		if err != nil {
			return nil, -1, -1, err
		}
		encryptionLength = el
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateThresholdedRandomPackets(noOfPackets, len(secretKey[0]),
				len(secretKey), &thPacket, xUsedCoords, encryptionLength)
		}
		sharePackets = append(sharePackets, thPacket)
	}
	return sharePackets, maxSharesPerPerson, encryptionLength, nil
}

func GenerateThresholdedPerPersonSharePackets(noOfSharesReceived int,
	allLeavesIndices [][]int, leavesData [][]shamir.PriShare,
	currentIndices *[]int, secretKey [][]uint16,
	parentSubsecrets map[int]map[uint16]shamir.PriShare,
	thPacket *ThresholdedPacket) (int, error) {
	// fmt.Println(parentSubsecrets)
	var encryptionLength int
	for ind, keyPart := range secretKey {
		// Firstly, add the encryption for that part of the key
		(*thPacket).RelevantEncryptions = append((*thPacket).RelevantEncryptions, [][]byte{})
		(*thPacket).ShareData = append((*thPacket).ShareData, []shamir.PriShare{})
		tempSecret := shamir.PriShare{X: uint16(0), Y: keyPart}
		noncedEncSecretKey, el, err := crypto_protocols.GetRelevantEncryptionBinExt((*thPacket).Nonce, tempSecret)
		if err != nil {
			return -1, err
		}
		(*thPacket).RelevantEncryptions[ind] = append((*thPacket).RelevantEncryptions[ind],
			noncedEncSecretKey)
		encryptionLength = el

		// Next, add the shares of that part of the key
		for j := 0; j < noOfSharesReceived; j++ {
			leafShareVal := leavesData[ind][allLeavesIndices[ind][(*currentIndices)[ind]]]
			parentSubsecret := parentSubsecrets[ind][leafShareVal.X]
			noncedEncryption, _, err := crypto_protocols.GetRelevantEncryptionBinExt((*thPacket).Nonce, parentSubsecret)
			if err != nil {
				log.Fatal(err)
				return -1, err
			}
			// If shares of the same subsecrets are being stored
			// then do not store the encryption twice
			// To keep the packets indistinguishable, store some random blobs
			// inside the packets
			if !crypto_protocols.GetEncryptionMembership((*thPacket).RelevantEncryptions[ind], noncedEncryption) {
				(*thPacket).RelevantEncryptions[ind] = append((*thPacket).RelevantEncryptions[ind], noncedEncryption)
			} else {
				randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
				if err != nil {
					log.Fatalln("Error in generating random packets")
				}
				(*thPacket).RelevantEncryptions[ind] = append((*thPacket).RelevantEncryptions[ind],
					randomBytes)
			}
			(*thPacket).ShareData[ind] = append((*thPacket).ShareData[ind], leafShareVal)
			(*currentIndices)[ind] += 1
		}
	}

	return encryptionLength, nil
}

func GenerateThresholdedRandomPackets(noOfPackets, relevantSize,
	keySize int,
	thPacket *ThresholdedPacket, xUsedCoords *[]uint16, encryptionLength int) {
	bufX := make([]byte, 2)
	bufY := make([]byte, 2*relevantSize)
	for i := 0; i < keySize; i++ {
		// This check is necessary to differentiate between a packet
		// distributed among trustees and non-trustees
		if len((*thPacket).ShareData) != keySize {
			(*thPacket).ShareData = append((*thPacket).ShareData, []shamir.PriShare{})
			(*thPacket).RelevantEncryptions = append((*thPacket).RelevantEncryptions, [][]byte{})
		}
		for j := 0; j < (noOfPackets); {
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
			(*xUsedCoords) = append((*xUsedCoords), x)
			randShareVal := shamir.PriShare{X: x, Y: y}
			(*thPacket).ShareData[i] = append((*thPacket).ShareData[i], randShareVal)
			randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			(*thPacket).RelevantEncryptions[i] = append((*thPacket).RelevantEncryptions[i],
				randomBytes)
			j++
		}
	}
}

func GetThresholdedAnonymityPackets(sharePackets []ThresholdedPacket,
	anonymitySetSize, maxSharesPerPerson, relevantSize, keySize int,
	xUsedCoords *[]uint16, encryptionLength int) ([]ThresholdedPacket, error) {
	var anonymityPackets []ThresholdedPacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var thPacket ThresholdedPacket
		nonce, _ := crypto_protocols.GenerateSalt32()
		thPacket.Nonce = nonce
		GenerateThresholdedRandomPackets(maxSharesPerPerson,
			relevantSize, keySize, &thPacket, xUsedCoords, encryptionLength)
		// Store an encryption that would be similar to the encryption of the
		// secret key
		// This is to ensure that the number of encryptions remains the same
		// in share packets and anonymity packets
		for j := 0; j < keySize; j++ {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			(thPacket).RelevantEncryptions[j] = append((thPacket).RelevantEncryptions[j],
				randomBytes)
		}

		anonymityPackets = append(anonymityPackets, thPacket)
	}
	return anonymityPackets, nil
}
