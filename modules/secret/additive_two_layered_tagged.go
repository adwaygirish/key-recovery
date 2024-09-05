package secret

import (
	"crypto/cipher"
	"log"
	"time"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	randm "math/rand"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

// The packet generation does not require any x-coordinates
// Therefore, there is no need to store any kind of marker info
// Storing only two salted hash works for our system
func GetAdditiveSharePacketsTagged(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, secretKey kyber.Scalar,
	trustees, absoluteThreshold int,
	leavesData []*share.PriShare, subsecrets []kyber.Scalar,
	parentSubsecrets map[*share.PriShare]kyber.Scalar,
	xUsedCoords *[]int) ([]AdditivePacket, int, map[int][]int, map[int][]int,
	error) {
	sharesInfo := make(map[int][]int)
	hashesInfo := make(map[int][]int)
	if absoluteThreshold > trustees {
		return nil, -1, nil, nil, errors.ErrInvalidThreshold
	}
	var anonymitySharePackets []AdditivePacket
	// Randomness will be used for setting the x-coordinate of the share
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
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
			GenerateAdditiveRandomPacketsTagged(g, randSeedShares, rng, noOfPackets,
				&addPacket, xUsedCoords, i, sharesInfo, hashesInfo)
		}
		anonymitySharePackets = append(anonymitySharePackets, addPacket)
	}
	return anonymitySharePackets, maxSharesPerPerson, sharesInfo, hashesInfo, nil
}

func GenerateAdditivePerPersonSharePacketsTagged(noOfSharesReceived int,
	leavesIndices []int, leavesData []*share.PriShare, currentIndex *int,
	secretKey kyber.Scalar, parentSubsecrets map[*share.PriShare]kyber.Scalar,
	addPacket *AdditivePacket, trusteesNum int,
	hashesInfo map[int][]int) {
	// Trustees store the salted hash of the secret key
	// Therefore, that information is always relevant
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretHash := crypto_protocols.GetSaltedHash((*addPacket).Salt, secretKeyBytes)
	(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes, secretHash)
	for j := 0; j < noOfSharesReceived; j++ {
		leafShareVal := leavesData[leavesIndices[*currentIndex]]
		parentSubsecret := parentSubsecrets[leafShareVal]
		parentSubsecretBytes := crypto_protocols.ConvertKeyToBytes(parentSubsecret)
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

func GenerateAdditiveRandomPacketsTagged(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, rng *randm.Rand, noOfPackets int,
	addPacket *AdditivePacket, xUsedCoords *[]int, trusteesNum int,
	sharesInfo, hashesInfo map[int][]int) {
	allXCoords := utils.GenerateIndicesSet(xSpace)
	for j := 0; j < (noOfPackets); j++ {
		relevantXCoords := utils.FindDifference(allXCoords, *xUsedCoords)
		indexXCoord := rng.Intn(len(relevantXCoords))
		xCoord := relevantXCoords[indexXCoord]
		(*xUsedCoords) = append((*xUsedCoords), xCoord)
		randShareVal := &share.PriShare{xCoord,
			g.Scalar().Pick(randSeedShares)}
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

func GetAdditiveAnonymityPacketsTagged(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, sharePackets []AdditivePacket,
	anonymitySetSize int, maxSharesPerPerson int,
	xUsedCoords *[]int, trusteesSharesInfo,
	trusteesHashesInfo map[int][]int) ([]AdditivePacket, map[int][]int,
	map[int][]int, error) {
	sharesInfo := make(map[int][]int)
	hashesInfo := make(map[int][]int)
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
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
		GenerateAdditiveRandomPacketsTagged(g, randSeedShares, rng,
			maxSharesPerPerson, &addPacket, xUsedCoords,
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
