package secret_binary_extension

import (
	"log"

	"crypto/rand"
	"encoding/binary"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
)

// The packet generation does not require any x-coordinates
// Therefore, there is no need to store any kind of marker info
// Storing only two salted hash works for our system
func GetAdditiveSharePacketsTagged(f shamir.Field,
	secretKey []uint16, relevantSize int,
	trustees, absoluteThreshold int,
	leavesData []shamir.PriShare, subsecrets [][]uint16,
	parentSubsecrets map[uint16][]uint16,
	xUsedCoords *[]uint16) ([]AdditivePacket, int, map[int][]int, map[int][]int,
	error) {
	sharesInfo := make(map[int][]int)
	hashesInfo := make(map[int][]int)
	if absoluteThreshold > trustees {
		return nil, -1, nil, nil, errors.ErrInvalidThreshold
	}
	var anonymitySharePackets []AdditivePacket
	totalShares := len(leavesData)
	sharesPerPerson := totalShares / trustees
	// Get how many shares each person should get
	personWiseShareDistribution, maxSharesPerPerson :=
		utils.GetPersonWiseShareNumber(trustees,
			totalShares, sharesPerPerson)
	// Indices of the leaves
	leavesIndices := utils.GenerateIndicesSet(totalShares)
	// Randomize the leaves that the trustees should receive
	utils.Shuffle(leavesIndices)
	currentIndex := 0
	for i := 0; i < trustees; i++ {
		sharesInfo[i] = make([]int, 0)
		hashesInfo[i] = make([]int, 0)
		var addPacket AdditivePacket
		noOfSharesReceived := personWiseShareDistribution[i]
		salt, _ := crypto_protocols.GenerateSalt32()
		addPacket.Salt = salt
		GenerateAdditivePerPersonSharePacketsTagged(noOfSharesReceived, leavesIndices,
			leavesData, &currentIndex, secretKey, parentSubsecrets, &addPacket,
			i, hashesInfo)
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateAdditiveRandomPacketsTagged(noOfPackets, relevantSize,
				&addPacket, xUsedCoords, i, sharesInfo, hashesInfo)
		}
		anonymitySharePackets = append(anonymitySharePackets, addPacket)
	}
	return anonymitySharePackets, maxSharesPerPerson, sharesInfo, hashesInfo, nil
}

func GenerateAdditivePerPersonSharePacketsTagged(noOfSharesReceived int,
	leavesIndices []int, leavesData []shamir.PriShare, currentIndex *int,
	secretKey []uint16, parentSubsecrets map[uint16][]uint16,
	addPacket *AdditivePacket, trusteesNum int,
	hashesInfo map[int][]int) {
	// Trustees store the salted hash of the secret key
	// Therefore, that information is always relevant
	// Convert the secret key to bytes for getting the hash
	secretKeyBytes := shamir.Uint16sToBytes(secretKey)
	// Get the salted hash of the secret key
	secretHash := crypto_protocols.GetSaltedHash((*addPacket).Salt, secretKeyBytes)
	(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes, secretHash)
	for j := 0; j < noOfSharesReceived; j++ {
		leafShareVal := leavesData[leavesIndices[*currentIndex]]
		parentSubsecret := parentSubsecrets[leafShareVal.X]
		parentSubsecretBytes := shamir.Uint16sToBytes(parentSubsecret)
		subsecretHash := crypto_protocols.GetSaltedHash((*addPacket).Salt,
			parentSubsecretBytes)
		// If the share of the same subsecrets are being stored
		// then do not store the hash twice
		// To keep the packets indistinguishable, store some random blobs
		// inside the packets
		if !crypto_protocols.GetHashMembership((*addPacket).RelevantHashes, subsecretHash) {
			(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes, subsecretHash)
		} else {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			randomHash := crypto_protocols.GetSHA256(randomBytes)
			(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes,
				randomHash)
			hashesInfo[trusteesNum] = append(hashesInfo[trusteesNum],
				len((*addPacket).RelevantHashes)-1)
		}
		(*addPacket).ShareData = append((*addPacket).ShareData, leafShareVal)
		(*currentIndex)++
	}
}

func GenerateAdditiveRandomPacketsTagged(noOfPackets int,
	relevantSize int,
	addPacket *AdditivePacket, xUsedCoords *[]uint16, trusteesNum int,
	sharesInfo, hashesInfo map[int][]int) {
	for j := 0; j < (noOfPackets); j++ {
		bufX := make([]byte, 2)
		// This is for getting random Y's
		bufY := make([]byte, 2*relevantSize)
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

		(*addPacket).ShareData = append((*addPacket).ShareData, randShareVal)
		sharesInfo[trusteesNum] = append(sharesInfo[trusteesNum], len((*addPacket).ShareData)-1)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		randomHash := crypto_protocols.GetSHA256(randomBytes)
		(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes,
			randomHash)
		hashesInfo[trusteesNum] = append(hashesInfo[trusteesNum],
			len((*addPacket).RelevantHashes)-1)
	}
}

func GetAdditiveAnonymityPacketsTagged(sharePackets []AdditivePacket,
	anonymitySetSize int, maxSharesPerPerson int, relevantSize int,
	xUsedCoords *[]uint16, trusteesSharesInfo,
	trusteesHashesInfo map[int][]int) ([]AdditivePacket, map[int][]int,
	map[int][]int, error) {
	sharesInfo := make(map[int][]int)
	hashesInfo := make(map[int][]int)
	var anonymityPackets []AdditivePacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Put all the information about trustees into the map
	for key, value := range trusteesSharesInfo {
		sharesInfo[key] = make([]int, 0)
		sharesInfo[key] = append(sharesInfo[key], value...)
	}
	for key, value := range trusteesHashesInfo {
		hashesInfo[key] = make([]int, 0)
		hashesInfo[key] = append(hashesInfo[key], value...)
	}
	noOfTrustees := len(sharePackets)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-noOfTrustees; i++ {
		sharesInfo[i+noOfTrustees] = make([]int, 0)
		sharesInfo[i+noOfTrustees] = make([]int, 0)
		var addPacket AdditivePacket
		salt, _ := crypto_protocols.GenerateSalt32()
		addPacket.Salt = salt
		GenerateAdditiveRandomPacketsTagged(
			maxSharesPerPerson, relevantSize, &addPacket, xUsedCoords,
			i+noOfTrustees, sharesInfo, hashesInfo)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		randomHash := crypto_protocols.GetSHA256(randomBytes)
		(addPacket).RelevantHashes = append((addPacket).RelevantHashes,
			randomHash)
		hashesInfo[i+noOfTrustees] = append(hashesInfo[i+noOfTrustees],
			len(addPacket.RelevantHashes)-1)
		anonymityPackets = append(anonymityPackets, addPacket)
	}
	return anonymityPackets, sharesInfo, hashesInfo, nil
}
