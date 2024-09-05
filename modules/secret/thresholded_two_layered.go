package secret

import (
	"crypto/cipher"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"

	"key_recovery/modules/errors"
	"log"
	randm "math/rand"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

type ThresholdedPacket struct {
	Nonce               [32]byte          // includes the list of salts used for each share
	RelevantEncryptions [][]byte          // includes the list of h(salt || parent secret)
	ShareData           []*share.PriShare // share data (for now only one share)
}

// This function generates thresholded shares of the secret
func GenerateTwoLayeredOptIndisShares(g kyber.Group, n int,
	secretKey kyber.Scalar, randSeedShares cipher.Stream, absoluteThreshold int,
	noOfSubsecrets int, percentageLeavesLayerThreshold,
	percentageUpperLayerThreshold int) ([]*share.PriShare, []*share.PriShare,
	map[*share.PriShare]*share.PriShare, []int, error) {
	// Shares which are to be distributed among the trustees
	var leavesData []*share.PriShare
	var subsecrets []*share.PriShare
	var xUsedCoords []int
	parentSubsecrets := make(map[*share.PriShare]*share.PriShare)

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
	GenerateThresholdedIndisUpperLayers(g, secretKey, randSeedShares, noOfSubsecrets,
		layerwiseThresholds[0], &subsecrets, &xUsedCoords)
	// Generate the shares for the leaves layer
	GenerateThresholdedIndisLeavesLayer(g, randSeedShares, absoluteThreshold,
		leavesNumbers, subsecrets, &leavesData, &xUsedCoords,
		parentSubsecrets)

	return subsecrets, leavesData, parentSubsecrets, xUsedCoords, nil
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the layers above the leaves
func GenerateThresholdedIndisUpperLayers(g kyber.Group, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, noOfSubsecrets int, subsecretsThreshold int,
	subsecrets *[]*share.PriShare, xUsedCoords *[]int) {
	// Generate Shamir's secret shares for the main secret
	shareVals := GenerateRandomXShares(g, subsecretsThreshold,
		noOfSubsecrets, secretKey, randSeedShares, xUsedCoords)
	(*subsecrets) = append((*subsecrets), shareVals...)

}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the leaves layer
// Leaves are distribute among the trustees
func GenerateThresholdedIndisLeavesLayer(g kyber.Group,
	randSeedShares cipher.Stream, absoluteThreshold int,
	leavesNumbers []int, subsecrets []*share.PriShare,
	leavesData *[]*share.PriShare, xUsedCoords *[]int,
	parentSubsecrets map[*share.PriShare]*share.PriShare) {
	for subsecretIndex, sharesNumber := range leavesNumbers {
		subsecretVal := subsecrets[subsecretIndex]
		shareVals := GenerateRandomXShares(g, absoluteThreshold,
			sharesNumber, subsecretVal.V, randSeedShares, xUsedCoords)
		*leavesData = append(*leavesData, shareVals...)
		for _, shareVal := range shareVals {
			parentSubsecrets[shareVal] = subsecretVal
		}
	}
}

func GetThresholdedSharePackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, secretKey kyber.Scalar,
	trustees, absoluteThreshold int,
	leavesData []*share.PriShare, subsecrets []*share.PriShare,
	parentSubsecrets map[*share.PriShare]*share.PriShare,
	xUsedCoords *[]int) ([]ThresholdedPacket, int, int, error) {
	if absoluteThreshold > trustees {
		return nil, -1, -1, errors.ErrInvalidThreshold
	}
	var sharePackets []ThresholdedPacket
	encryptionLength := 0
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
		var thPacket ThresholdedPacket
		noOfSharesReceived := personWiseShareDistribution[i]
		nonce, _ := crypto_protocols.GenerateSalt32()
		thPacket.Nonce = nonce
		el, err := GenerateThresholdedPerPersonSharePackets(noOfSharesReceived,
			leavesIndices, leavesData, &currentIndex, secretKey,
			parentSubsecrets, &thPacket)
		if err != nil {
			return nil, -1, -1, err
		}
		encryptionLength = el
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateThresholdedRandomPackets(g, randSeedShares, rng, noOfPackets,
				&thPacket, xUsedCoords, encryptionLength)
		}
		sharePackets = append(sharePackets, thPacket)
	}
	return sharePackets, maxSharesPerPerson, encryptionLength, nil
}

func GenerateThresholdedPerPersonSharePackets(noOfSharesReceived int,
	leavesIndices []int, leavesData []*share.PriShare, currentIndex *int,
	secretKey kyber.Scalar, parentSubsecrets map[*share.PriShare]*share.PriShare,
	thPacket *ThresholdedPacket) (int, error) {
	tempSecret := &share.PriShare{I: 0, V: secretKey}
	var encryptionLength int
	noncedEncSecretKey, encryptionLength, err := crypto_protocols.GetRelevantEncryption((*thPacket).Nonce, tempSecret)
	if err != nil {
		return -1, err
	}
	(*thPacket).RelevantEncryptions = append((*thPacket).RelevantEncryptions,
		noncedEncSecretKey)
	for j := 0; j < noOfSharesReceived; j++ {
		leafShareVal := leavesData[leavesIndices[*currentIndex]]
		parentSubsecret := parentSubsecrets[leafShareVal]
		noncedEncryption, _, err := crypto_protocols.GetRelevantEncryption((*thPacket).Nonce, parentSubsecret)
		if err != nil {
			log.Fatal(err)
			return -1, err
		}
		// If the share of the same subsecrets are being stored
		// then do not store the hash twice
		// To keep the packets indistinguishable, store some random blobs
		// inside the packets
		if !crypto_protocols.GetEncryptionMembership((*thPacket).RelevantEncryptions, noncedEncryption) {
			(*thPacket).RelevantEncryptions = append((*thPacket).RelevantEncryptions, noncedEncryption)
		} else {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			(*thPacket).RelevantEncryptions = append((*thPacket).RelevantEncryptions,
				randomBytes)
		}
		(*thPacket).ShareData = append((*thPacket).ShareData, leafShareVal)
		(*currentIndex)++
	}
	return encryptionLength, nil
}

func GenerateThresholdedRandomPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, rng *randm.Rand, noOfPackets int,
	thPacket *ThresholdedPacket, xUsedCoords *[]int, encryptionLength int) {
	allXCoords := utils.GenerateIndicesSet(xSpace)
	for j := 0; j < (noOfPackets); j++ {
		relevantXCoords := utils.FindDifference(allXCoords, *xUsedCoords)
		indexXCoord := rng.Intn(len(relevantXCoords))
		xCoord := relevantXCoords[indexXCoord]
		(*xUsedCoords) = append((*xUsedCoords), xCoord)
		randShareVal := &share.PriShare{xCoord,
			g.Scalar().Pick(randSeedShares)}
		(*thPacket).ShareData = append((*thPacket).ShareData, randShareVal)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		(*thPacket).RelevantEncryptions = append((*thPacket).RelevantEncryptions,
			randomBytes)
	}
}

func GetThresholdedAnonymityPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, sharePackets []ThresholdedPacket,
	anonymitySetSize int, maxSharesPerPerson int,
	xUsedCoords *[]int, encryptionLength int) ([]ThresholdedPacket, error) {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	var anonymityPackets []ThresholdedPacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var thPacket ThresholdedPacket
		nonce, _ := crypto_protocols.GenerateSalt32()
		thPacket.Nonce = nonce
		GenerateThresholdedRandomPackets(g, randSeedShares, rng,
			maxSharesPerPerson, &thPacket, xUsedCoords, encryptionLength)
		// Store an encryption that would be similar to the encryption of the
		// secret key
		// This is to ensure that the number of encryptions remains the same
		// in share packets and anonymity packets
		randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		(thPacket).RelevantEncryptions = append((thPacket).RelevantEncryptions,
			randomBytes)
		anonymityPackets = append(anonymityPackets, thPacket)
	}
	return anonymityPackets, nil
}
