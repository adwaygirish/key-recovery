package secret

import (
	"crypto/cipher"
	"fmt"
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

type AdditivePacket struct {
	Salt           [32]byte          // includes the list of salts used for each share
	RelevantHashes [][32]byte        // includes the list of h(salt || parent secret)
	ShareData      []*share.PriShare // share data (for now only one share)
}

var routinesMap = map[int]int{
	20:  2,
	40:  4,
	100: 8,
	400: 16,
}

var xSpace int = 5000

// This function simply provides the shares
// It provides shares at random x-coordinates
// Generating shares by using this method ensures that all the
// shares are at different points and thus, an adversary cannot get any
// information about which layer the secret is from
func GenerateRandomXShares(g kyber.Group, t int, n int, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, xUsedCoords *[]int) []*share.PriShare {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	polynomial := share.NewPriPoly(g, t, secretKey, randSeedShares)
	shareValsSet := polynomial.Shares(xSpace)
	shareVals := make([]*share.PriShare, 0, n)
	allXCoords := utils.GenerateIndicesSet(xSpace)
	for i := 0; i < n; i++ {
		relevantXCoords := utils.FindDifference(allXCoords, *xUsedCoords)
		indexXCoord := rng.Intn(len(relevantXCoords))
		xCoord := relevantXCoords[indexXCoord]
		(*xUsedCoords) = append((*xUsedCoords), xCoord)
		shareVals = append(shareVals, shareValsSet[xCoord])
	}
	return shareVals
}

// This function is for additive secret sharing in the subsecrets layer
// This makes our life simpler and also makes the explanation of our code
// way simpler
// Hence, for this design, we do not need the percentage of threshold in the
// the subsecrets level
func GenerateAdditiveTwoLayeredOptIndisShares(g kyber.Group, n int,
	secretKey kyber.Scalar, randSeedShares cipher.Stream, absoluteThreshold int,
	noOfSubsecrets int,
	percentageLeavesLayerThreshold int) ([]kyber.Scalar, []*share.PriShare,
	map[*share.PriShare]kyber.Scalar, []int, error) {
	// Shares which are to be distributed among the trustees
	var leavesData []*share.PriShare
	var xUsedCoords []int
	var subsecrets []kyber.Scalar
	parentSubsecrets := make(map[*share.PriShare]kyber.Scalar)

	// If the percentage threshold is greater than 100, then it does not make
	// sense to run the recovery
	if percentageLeavesLayerThreshold > 100 {
		return nil, nil, nil, nil, errors.ErrInvalidThreshold
	}

	leavesNumbers := utils.GenerateAdditiveTwoLayeredTree(
		n, percentageLeavesLayerThreshold, absoluteThreshold, noOfSubsecrets)
	// Generate the shares for all the layers except the leaves layer
	GenerateAdditiveIndisUpperLayers(g, secretKey, randSeedShares,
		noOfSubsecrets, &subsecrets, &xUsedCoords)
	// Generate the shares for the leaves layer
	GenerateAdditiveIndisLeavesLayer(g, randSeedShares, absoluteThreshold,
		leavesNumbers, subsecrets, &leavesData, &xUsedCoords,
		parentSubsecrets)

	return subsecrets, leavesData, parentSubsecrets, xUsedCoords, nil
}

// This function is called by the GenerateAdditiveTwoLayeredOptIndisShares
// for generating shares of the layers above the leaves
// Simply generates (n-1) random points and then, generates the point which is
// secret key minus the sum of the (n-1) points
func GenerateAdditiveIndisUpperLayers(g kyber.Group, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, noOfSubsecrets int,
	subsecrets *[]kyber.Scalar, xUsedCoords *[]int) {
	// Summation of the subsecrets that will be generated
	sharesSum := g.Scalar().Pick(randSeedShares)
	firstShare := g.Scalar().Pick(randSeedShares)
	firstShare = firstShare.Set(sharesSum)
	(*subsecrets) = append((*subsecrets), firstShare)
	for i := 1; i < noOfSubsecrets-1; i++ {
		shareVal := g.Scalar().Pick(randSeedShares)
		(*subsecrets) = append((*subsecrets), shareVal)
		sharesSum = sharesSum.Add(sharesSum, shareVal)
	}
	shareVal := g.Scalar().Pick(randSeedShares)
	shareVal = shareVal.Sub(secretKey, sharesSum)
	sharesSum = sharesSum.Add(sharesSum, shareVal)
	(*subsecrets) = append((*subsecrets), shareVal)
}

// This function is called by the GenerateAdditiveTwoLayeredOptIndisShares
// for generating the leaves layer
func GenerateAdditiveIndisLeavesLayer(g kyber.Group,
	randSeedShares cipher.Stream, absoluteThreshold int,
	leavesNumbers []int, subsecrets []kyber.Scalar,
	leavesData *[]*share.PriShare, xUsedCoords *[]int,
	parentSubsecrets map[*share.PriShare]kyber.Scalar) {
	for subsecretIndex, sharesNumber := range leavesNumbers {
		subsecretVal := subsecrets[subsecretIndex]
		shareVals := GenerateRandomXShares(g, absoluteThreshold,
			sharesNumber, subsecretVal, randSeedShares, xUsedCoords)
		// fmt.Println(shareVals)
		*leavesData = append(*leavesData, shareVals...)
		for _, shareVal := range shareVals {
			parentSubsecrets[shareVal] = subsecretVal
		}
	}
}

// The packet generation does not require any x-coordinates
// Therefore, there is no need to store any kind of marker info
// Storing only two salted hash works for our system
func GetAdditiveSharePackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, secretKey kyber.Scalar,
	trustees, absoluteThreshold int,
	leavesData []*share.PriShare, subsecrets []kyber.Scalar,
	parentSubsecrets map[*share.PriShare]kyber.Scalar,
	xUsedCoords *[]int) ([]AdditivePacket, int, error) {
	if absoluteThreshold > trustees {
		return nil, -1, errors.ErrInvalidThreshold
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
		var addPacket AdditivePacket
		noOfSharesReceived := personWiseShareDistribution[i]
		salt, _ := crypto_protocols.GenerateSalt32()
		addPacket.Salt = salt
		GenerateAdditivePerPersonSharePackets(noOfSharesReceived, leavesIndices,
			leavesData, &currentIndex, secretKey, parentSubsecrets, &addPacket)
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateAdditiveRandomPackets(g, randSeedShares, rng, noOfPackets,
				&addPacket, xUsedCoords)
		}
		anonymitySharePackets = append(anonymitySharePackets, addPacket)
	}
	return anonymitySharePackets, maxSharesPerPerson, nil
}

func GenerateAdditivePerPersonSharePackets(noOfSharesReceived int,
	leavesIndices []int, leavesData []*share.PriShare, currentIndex *int,
	secretKey kyber.Scalar, parentSubsecrets map[*share.PriShare]kyber.Scalar,
	addPacket *AdditivePacket) {
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
		}
		(*addPacket).ShareData = append((*addPacket).ShareData, leafShareVal)
		(*currentIndex)++
	}
}

func GenerateAdditiveRandomPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, rng *randm.Rand, noOfPackets int,
	addPacket *AdditivePacket, xUsedCoords *[]int) {
	allXCoords := utils.GenerateIndicesSet(xSpace)
	for j := 0; j < (noOfPackets); j++ {
		relevantXCoords := utils.FindDifference(allXCoords, *xUsedCoords)
		indexXCoord := rng.Intn(len(relevantXCoords))
		xCoord := relevantXCoords[indexXCoord]
		(*xUsedCoords) = append((*xUsedCoords), xCoord)
		randShareVal := &share.PriShare{xCoord,
			g.Scalar().Pick(randSeedShares)}
		(*addPacket).ShareData = append((*addPacket).ShareData, randShareVal)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		randomHash := crypto_protocols.GetSHA256(randomBytes)
		(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes,
			randomHash)
	}
}

func GetAdditiveAnonymityPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, sharePackets []AdditivePacket,
	anonymitySetSize int, maxSharesPerPerson int,
	xUsedCoords *[]int) ([]AdditivePacket, error) {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	var anonymityPackets []AdditivePacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var addPacket AdditivePacket
		salt, _ := crypto_protocols.GenerateSalt32()
		addPacket.Salt = salt
		GenerateAdditiveRandomPackets(g, randSeedShares, rng,
			maxSharesPerPerson, &addPacket, xUsedCoords)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		randomHash := crypto_protocols.GetSHA256(randomBytes)
		(addPacket).RelevantHashes = append((addPacket).RelevantHashes,
			randomHash)
		anonymityPackets = append(anonymityPackets, addPacket)
	}
	return anonymityPackets, nil
}

// This function is meant to work for
// Since the time taken is exponential for the larger thresholds,
// we break the shares into smaller pieces and distribute it among people
// This function does not use any additional information during the
// recovery - that is the user only hashes and the anonymity set
func AdditiveOptIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	anonymityPackets []AdditivePacket, accessOrder []int,
	absoluteThreshold int) kyber.Scalar {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	var usedShares []*share.PriShare
	var obtainedSubsecrets []kyber.Scalar
	var recoveredKey kyber.Scalar
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		// fmt.Println(obtainedPacketsIndices)
		var peoplePackets []AdditivePacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		PersonwiseAdditiveOptIndisSecretRecovery(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseAdditiveOptIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []AdditivePacket, absoluteThreshold int,
	usedShares *[]*share.PriShare, obtainedSubsecrets *[]kyber.Scalar,
	secretRecovered *bool, recoveredKey *kyber.Scalar) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}
	// fmt.Println(allShareData, "tttttt")
	// Do not use the shares which have been already used for recovery
	relevantShareData, err := crypto_protocols.GetSharesSetDifference(allShareData,
		*usedShares)
	if err != nil {
		log.Fatal(err)
	}
	if len(relevantShareData) < absoluteThreshold {
		return
	}

	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i]] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, i)
		}
	}

	shareIndicesSet := utils.GenerateIndicesSet(len(relevantShareData))
	// fmt.Println(len(relevantShareData), len(allShareData), "xxxxx")

	// if (len(allShareData)-len(relevantShareData))%5 != 0 {
	// 	fmt.Println(len(*usedShares))
	// 	fmt.Println(len(*obtainedSubsecrets))
	// 	fmt.Println(*obtainedSubsecrets)
	// }
	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubset [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubset = append(relevantIndicesSubset, indicesSubset)
		}
	}
	fmt.Println("No. of combinations", len(relevantIndicesSubset),
		len(allIndicesSubset), len(relevantIndices), relevantIndices)

	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubset {
		// Create the subset for running the recovery

		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		// Get the recovered secret from the absoluteThreshold number of shares
		recovered, err := share.RecoverSecret(g, relevantSubset,
			absoluteThreshold, absoluteThreshold)
		if err != nil {
			fmt.Println(relevantSubset, indicesSet)
			log.Fatal(err)
		}
		// Considering the hashes and marker info of only one person in
		// the subset is enough
		runRelevantHashes := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantHashes
		runRelevantSalt := peoplePackets[shareDataMap[relevantSubset[0]]].Salt
		isHashMatched, _, err := LeavesAdditiveIndisRecovery(g,
			recovered, relevantSubset, runRelevantHashes,
			runRelevantSalt, obtainedSubsecrets, usedShares)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isHashMatched && len((*obtainedSubsecrets)) > 1 {
			SubsecretsAdditiveIndisRecovery(g, randSeedShares, runRelevantHashes, runRelevantSalt,
				*obtainedSubsecrets, secretRecovered, recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func LeavesAdditiveIndisRecovery(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantHashes [][32]byte, runRelevantSalt [32]byte,
	obtainedSubsecrets *[]kyber.Scalar,
	usedShares *[]*share.PriShare) (bool, [32]byte, error) {
	isHashMatched, matchedHash, err := crypto_protocols.GetAdditiveIndisShareMatch(
		recovered, runRelevantHashes, runRelevantSalt)
	if err != nil {
		log.Fatalln(err)
		return false, matchedHash, err
	}
	if isHashMatched {
		for _, relevantShare := range relevantSubset {
			if !crypto_protocols.CheckShareAlreadyUsed(*usedShares, relevantShare) {
				*usedShares = append(*usedShares, relevantShare)
			}
		}
		if !crypto_protocols.CheckSubsecretAlreadyRecovered(*obtainedSubsecrets,
			recovered) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
		}
		// fmt.Println(len(relevantSubset))
		// fmt.Println(relevantSubset)
	}
	return isHashMatched, matchedHash, nil
}

func SubsecretsAdditiveIndisRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte,
	obtainedSubsecrets []kyber.Scalar, secretRecovered *bool,
	recoveredKey *kyber.Scalar) {
	*secretRecovered, *recoveredKey = crypto_protocols.GetAdditiveSaltedHashMatch(g, randSeedShares, runRelevantHashes, runRelevantSalt, obtainedSubsecrets)
}
