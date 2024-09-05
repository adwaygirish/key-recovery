package secret

import (
	"crypto/cipher"
	"fmt"
	"log"
	randm "math/rand"
	"time"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"

	"key_recovery/modules/errors"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

type Packet struct {
	Salt           [32]byte          // includes the list of salts used for each share
	RelevantHashes [][32]byte        // includes the list of h(salt || parent secret)
	ShareData      []*share.PriShare // share data (for now only one share)
	MarkerInfo     [][]byte          // x-coordinate of the parent share and for finding out if the secret key was recovered
}

// This function generates full threshold shares of the secret
func GenerateFTOptIndisShares(g kyber.Group, t int, n int, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, largestShareSetSize int,
	smallestShareSetSize int) (map[[32]byte][]*share.PriShare,
	map[[32]byte]kyber.Scalar, int, map[[32]byte]int, map[[32]byte]int,
	map[[32]byte]int, []*share.PriShare, [][32]byte, [32]byte,
	map[*share.PriShare]*share.PriShare, []int, error) {
	// Store the shares in a 2D slice
	// The shares in a particular slice correspond to the same secret
	outputShares := make(map[[32]byte][]*share.PriShare)
	// Store the hashes of the secret for which the shares have been created
	outputSecretHashes := make(map[[32]byte]kyber.Scalar)
	var noOfLevels int
	// The level of the shares
	hashLevels := make(map[[32]byte]int)
	// No. of shares of the secret
	noOfShares := make(map[[32]byte]int)
	// Thresholds for various secrets
	thresholds := make(map[[32]byte]int)
	// Shares which are to be distributed among the trustees
	var leavesData []*share.PriShare
	// List of hashes of various secrets
	var outputSecretHashesSlice [][32]byte
	// Shares of the penultimate level (just above the leaves)
	var penultimateShares []*share.PriShare
	// Hash of the secret key
	var secretKeyHash [32]byte
	var xUsedCoords []int
	parentSecrets := make(map[*share.PriShare]*share.PriShare)

	if t > n {
		return nil, nil, 0, nil, nil, nil, nil, nil, [32]byte{}, nil, nil, errors.ErrInvalidThreshold
	}

	// When the threshold is less than 5
	// Simple generate shares of the secret and distribute them
	if n <= 5 {
		tempSecretKeyShare := &share.PriShare{I: 0, V: secretKey}
		shareVals := GenerateRandomXShares(g, n, n, secretKey, randSeedShares, &xUsedCoords)
		// Obtain the hash in []byte
		secretKeyHash = crypto_protocols.GetValSHA256(secretKey)
		outputShares[secretKeyHash] = shareVals
		outputSecretHashes[secretKeyHash] = secretKey
		outputSecretHashesSlice = append(outputSecretHashesSlice, secretKeyHash)
		hashLevels[secretKeyHash] = 0
		leavesData = append(leavesData, shareVals...)
		for _, shareVal := range shareVals {
			parentSecrets[shareVal] = tempSecretKeyShare
		}
		noOfLevels = 1
	} else {
		// When the threshold is greater than 5
		// Go for the hierarchical approach
		nol, distribution, leavesNumbers, layerwiseThresholds := utils.MulSplitShares(n,
			largestShareSetSize, smallestShareSetSize)
		noOfLevels = nol
		// Generate the shares for all the layers except the leaves layer
		GenerateIndisUpperLayers(g, secretKey, randSeedShares, noOfLevels,
			distribution, layerwiseThresholds, outputShares, outputSecretHashes,
			hashLevels, noOfShares, thresholds, &outputSecretHashesSlice,
			&penultimateShares, &secretKeyHash, parentSecrets, &xUsedCoords)
		// Generate the shares for the leaves layer
		GenerateIndisLeavesLayer(g, randSeedShares, leavesNumbers,
			layerwiseThresholds[len(layerwiseThresholds)-1], noOfLevels,
			outputShares, outputSecretHashes, hashLevels, noOfShares, thresholds,
			&outputSecretHashesSlice, &penultimateShares, &leavesData,
			parentSecrets, &xUsedCoords)
	}

	return outputShares, outputSecretHashes, noOfLevels, hashLevels, noOfShares,
		thresholds, leavesData, outputSecretHashesSlice,
		secretKeyHash, parentSecrets, xUsedCoords, nil
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the layers above the leaves
func GenerateIndisUpperLayers(g kyber.Group, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, noOfLevels int, distribution []int,
	layerwiseThresholds []int, outputShares map[[32]byte][]*share.PriShare,
	outputSecretHashes map[[32]byte]kyber.Scalar,
	hashLevels map[[32]byte]int, noOfShares map[[32]byte]int,
	thresholds map[[32]byte]int, outputSecretHashesSlice *[][32]byte,
	penultimateShares *[]*share.PriShare,
	secretKeyHash *[32]byte, parentSecrets map[*share.PriShare]*share.PriShare,
	xUsedCoords *[]int) {
	// This is just a temporary variable created for the code to run
	tempSecret := &share.PriShare{I: 0, V: secretKey}
	*secretKeyHash = crypto_protocols.GetValSHA256(secretKey)
	layerSecrets := []*share.PriShare{(tempSecret)}
	var nextLayerSecrets []*share.PriShare
	for i := 0; i < noOfLevels-1; i++ {
		noOfSharesPerSecret := distribution[i]
		layerThreshold := layerwiseThresholds[i]
		// For now, we consider full threshold
		for _, layerSecret := range layerSecrets {
			shareVals := GenerateRandomXShares(g, layerThreshold,
				noOfSharesPerSecret, layerSecret.V, randSeedShares, xUsedCoords)
			layerSecretHash := crypto_protocols.GetValSHA256(layerSecret.V)
			outputShares[layerSecretHash] = shareVals
			outputSecretHashes[layerSecretHash] = layerSecret.V
			*outputSecretHashesSlice = append(*outputSecretHashesSlice,
				layerSecretHash)
			hashLevels[layerSecretHash] = i
			noOfShares[layerSecretHash] = noOfSharesPerSecret
			thresholds[layerSecretHash] = noOfSharesPerSecret
			if i == noOfLevels-2 {
				*penultimateShares = append(*penultimateShares,
					shareVals...)
			}
			for _, shareVal := range shareVals {
				parentSecrets[shareVal] = layerSecret
			}
			nextLayerSecrets = append(nextLayerSecrets, shareVals...)
		}
		layerSecrets = nextLayerSecrets
	}
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the leaves layer
// Leaves are distribute among the trustees
func GenerateIndisLeavesLayer(g kyber.Group, randSeedShares cipher.Stream,
	leavesNumbers []int, leavesLayerThreshold int, noOfLevels int,
	outputShares map[[32]byte][]*share.PriShare,
	outputSecretHashes map[[32]byte]kyber.Scalar,
	hashLevels map[[32]byte]int, noOfShares map[[32]byte]int,
	thresholds map[[32]byte]int, outputSecretHashesSlice *[][32]byte,
	penultimateShares *[]*share.PriShare, leavesData *[]*share.PriShare,
	parentSecrets map[*share.PriShare]*share.PriShare, xUsedCoords *[]int) {
	for shareIndex, sharesNumber := range leavesNumbers {
		secretVal := (*penultimateShares)[shareIndex]
		layerSecret := secretVal
		shareVals := GenerateRandomXShares(g, leavesLayerThreshold,
			sharesNumber, layerSecret.V, randSeedShares, xUsedCoords)
		layerSecretHash := crypto_protocols.GetValSHA256(layerSecret.V)
		outputShares[layerSecretHash] = shareVals
		outputSecretHashes[layerSecretHash] = layerSecret.V
		*outputSecretHashesSlice = append(*outputSecretHashesSlice,
			layerSecretHash)
		hashLevels[layerSecretHash] = noOfLevels - 1
		noOfShares[layerSecretHash] = sharesNumber
		thresholds[layerSecretHash] = sharesNumber
		*leavesData = append(*leavesData, shareVals...)
		for _, shareVal := range shareVals {
			parentSecrets[shareVal] = layerSecret
		}
	}
}

// This function creates packets with salt, h(parent secret || salt),
// h(root secret || salt), and share
func GetSharePackets(g *edwards25519.SuiteEd25519, randSeedShares cipher.Stream,
	trustees int, threshold int, leavesData []*share.PriShare,
	secretKey kyber.Scalar, outputShares map[[32]byte][]*share.PriShare,
	outputSecretHashes map[[32]byte]kyber.Scalar, noOfLevels int,
	hashLevels map[[32]byte]int, secretKeyHash [32]byte,
	parentSecrets map[*share.PriShare]*share.PriShare,
	xUsedCoors *[]int) ([]Packet, int, int, error) {
	if threshold > trustees {
		return nil, -1, -1, errors.ErrInvalidThreshold
	}
	var anonymityPackets []Packet
	var encryptionLength int
	// Randomness will be used for setting the x-coordinate of the share
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	offset := 500
	maxCoordinateX := 500
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
		var packet Packet
		noOfSharesReceived := personWiseShareDistribution[i]
		var shareVals []*share.PriShare
		var relevantSecrets [][]*share.PriShare
		salt, _ := crypto_protocols.GenerateSalt32()
		packet.Salt = salt
		// Start storing the share packets
		// Store the shares and the relevant hashes
		GeneratePerPersonSharePackets(noOfSharesReceived, leavesIndices,
			&relevantSecrets, leavesData, &currentIndex, secretKeyHash,
			parentSecrets, &shareVals, &packet)
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateRandomPackets(g, randSeedShares, rng, noOfLevels,
				noOfPackets, offset, maxCoordinateX, &shareVals, &packet,
				xUsedCoors)
		}
		packet.ShareData = shareVals
		// Marker information stores information about the x-coordinates
		// and a blob that indicates that the secret key has been retrieved
		markerOutput, encryptionL, err := crypto_protocols.GetMarkerInfo(secretKey,
			relevantSecrets, salt, shareVals, noOfSharesReceived,
			noOfLevels)
		encryptionLength = encryptionL
		if err != nil {
			if err == errors.ErrBytesNotEqual {
				fmt.Println("Tree not generated properly")
			}
			return nil, -1, -1, err
		}
		packet.MarkerInfo = append(packet.MarkerInfo, markerOutput...)
		anonymityPackets = append(anonymityPackets, packet)
	}
	return anonymityPackets, maxSharesPerPerson, encryptionLength, nil
}

// This function creates packets for trustees
// For each person, this function proceeds with one share at a time
// For each secret, it starts at the leaf and stores the information until
// the root (main secret)
func GeneratePerPersonSharePackets(noOfSharesReceived int, leavesIndices []int,
	relevantSecrets *[][]*share.PriShare, leavesData []*share.PriShare,
	currentIndex *int, secretKeyHash [32]byte,
	parentSecrets map[*share.PriShare]*share.PriShare,
	shareVals *[]*share.PriShare, packet *Packet) {
	for j := 0; j < noOfSharesReceived; j++ {
		// For each share that the person will receive
		// Create a slice
		*relevantSecrets = append(*relevantSecrets, []*share.PriShare{})
		shareVal := leavesData[leavesIndices[*currentIndex]]
		*shareVals = append(*shareVals, shareVal)
		// salt, _ := crypto_protocols.GenerateSalt32()
		for {
			parentSecret := parentSecrets[shareVal]
			(*relevantSecrets)[j] = append((*relevantSecrets)[j], parentSecret)
			// Store the salted hash of the y-coordinates
			parentSecretBytes := crypto_protocols.ConvertKeyToBytes(parentSecret.V)
			saltedHash := crypto_protocols.GetSaltedHash((*packet).Salt,
				parentSecretBytes)
			(*packet).RelevantHashes = append((*packet).RelevantHashes, saltedHash)
			shareVal = parentSecret
			// When you have the root of the tree, then you stop the iteration
			if crypto_protocols.CheckHashesEqual(crypto_protocols.GetValSHA256(shareVal.V), secretKeyHash) {
				break
			}
		}
		// This is so that the x-index of all the shares are different
		(*currentIndex)++
	}
}

// This function is meant for generating random shares
// This is necessary for random packets for users with less shares and
// for generating the packets in the anonymity set
func GenerateRandomPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, rng *randm.Rand, noOfLevels int,
	noOfPackets int, offset int, maxCoordinateX int,
	shareVals *[]*share.PriShare, packet *Packet, xUsedCoords *[]int) {
	allXCoords := utils.GenerateIndicesSet(xSpace)
	for j := 0; j < (noOfPackets); j++ {
		relevantXCoords := utils.FindDifference(allXCoords, *xUsedCoords)
		indexXCoord := rng.Intn(len(relevantXCoords))
		xCoord := relevantXCoords[indexXCoord]
		(*xUsedCoords) = append((*xUsedCoords), xCoord)
		randShareVal := &share.PriShare{xCoord,
			g.Scalar().Pick(randSeedShares)}
		(*shareVals) = append((*shareVals), randShareVal)
		for k := 0; k < noOfLevels; k++ {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
			if err != nil {
				fmt.Println("Error in generating random packets")
			}
			// For the hash in a random packet, it is simply a random string
			// of bytes
			randomHash := crypto_protocols.GetSHA256(randomBytes)
			(*packet).RelevantHashes = append((*packet).RelevantHashes,
				randomHash)
		}
	}
}

// This function meant for generating packets for acquaintances
func GetAnonymityPackets(g *edwards25519.SuiteEd25519, randSeedShares cipher.Stream,
	sharePackets []Packet, anonymitySetSize int, maxSharesPerPerson int,
	noOfLevels int, encryptionLength int, xUsedCoords *[]int) ([]Packet, error) {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	var anonymityPackets []Packet
	offset := 1000
	maxCoordinateX := 500
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)

	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var shareVals []*share.PriShare
		var packet Packet
		packet.Salt, _ = crypto_protocols.GenerateSalt32()
		GenerateRandomPackets(g, randSeedShares, rng, noOfLevels,
			maxSharesPerPerson, offset, maxCoordinateX, &shareVals, &packet,
			xUsedCoords)
		packet.ShareData = shareVals
		blobsNumber := len(packet.RelevantHashes)
		markerOutput, err := crypto_protocols.GetAnonymityMarkerInfo(encryptionLength, blobsNumber)
		if err != nil {
			if err == errors.ErrBytesNotEqual {
				fmt.Println("Tree not generated properly")
			}
			return nil, err
		}
		packet.MarkerInfo = append(packet.MarkerInfo, markerOutput...)
		anonymityPackets = append(anonymityPackets, packet)
	}
	return anonymityPackets, nil
}

// This function is meant to work for full threshold
// Since the time taken is exponential for the larger thresholds,
// we break the shares into smaller pieces and distribute it among people
// This function does not use any additional information during the
// recovery - that is the user only hashes and the anonymity set
func FTOptIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	anonymityPackets []Packet, accessOrder []int,
	largestShareSetSize int) kyber.Scalar {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	firstSecretRecovered := false
	var usedShares []*share.PriShare
	var usedHashes [][32]byte
	var usedMarkerInfo [][]byte
	var allLayersRelevantShares [][]*share.PriShare
	var recoveredKey kyber.Scalar
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		smallerThreshold := utils.GetSmallerValue(obtainedLength,
			largestShareSetSize)
		var peoplePackets []Packet
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		PersonwiseFTOptIndisSecretRecovery(g, peoplePackets,
			largestShareSetSize, &usedShares, &usedHashes, &usedMarkerInfo,
			smallerThreshold, &allLayersRelevantShares, &firstSecretRecovered,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

// This function is run as a user obtains secrets from a person
func PersonwiseFTOptIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	peoplePackets []Packet, largestShareSetSize int,
	usedShares *[]*share.PriShare, usedHashes *[][32]byte,
	usedMarkerInfo *[][]byte, smallerThreshold int,
	allLayersRelevantShares *[][]*share.PriShare, firstSecretRecovered *bool,
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
	// Do not use the shares which have been already used for recovery
	relevantShareData, err := crypto_protocols.GetSharesSetDifference(allShareData,
		*usedShares)
	if err != nil {
		log.Fatal(err)
	}
	shareIndicesSet := utils.GenerateIndicesSet(len(relevantShareData))
	for th := 2; th <= smallerThreshold; th++ {
		// Generate all the possible combinations of the shares
		allIndicesSet := utils.GenerateSubsetsOfSize(shareIndicesSet, th)

		for _, indicesSet := range allIndicesSet {
			var relevantSubset []*share.PriShare
			for _, index := range indicesSet {
				relevantSubset = append(relevantSubset,
					relevantShareData[index])
			}
			// Get the recovered secret from the shares
			recovered, err := share.RecoverSecret(g, relevantSubset,
				len(relevantSubset), len(relevantSubset))
			if err != nil {
				fmt.Println(relevantSubset)
				log.Fatal(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			// allHashes := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantHashes
			runRelevantHashes := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantHashes
			// runRelevantHashes, err := crypto_protocols.GetHashesSetDifference(allHashes, *usedHashes)
			if err != nil {
				log.Fatalln(err)
			}
			// allMarkerInfo := peoplePackets[shareDataMap[relevantSubset[0]]].MarkerInfo
			// runRelevantMarkerInfo, err := crypto_protocols.GetMarkerInfoDifference(allMarkerInfo, *usedMarkerInfo)
			runRelevantMarkerInfo := peoplePackets[shareDataMap[relevantSubset[0]]].MarkerInfo
			if err != nil {
				log.Fatalln(err)
			}
			runRelevantSalt := peoplePackets[shareDataMap[relevantSubset[0]]].Salt
			isHashMatched, isCorrect, err := HierarchicalInDisSecretRecovery(g, recovered, relevantSubset,
				runRelevantHashes, runRelevantMarkerInfo, runRelevantSalt,
				allLayersRelevantShares, usedShares, firstSecretRecovered,
				secretRecovered, recoveredKey)
			if err != nil {
				// fmt.Println(recovered)
				// fmt.Println(relevantSubset[0])
				// fmt.Println(runRelevantMarkerInfo)
				// fmt.Println("Wrongxx")
				// fmt.Println(isHashMatched)
				log.Fatalln(err)
				return
			}
			// If some secret has been recovered, then update the hashes and
			// the marker info already obtained
			// fmt.Println("zoom", recovered, )
			if isCorrect && isHashMatched {
				err = UpdateUsedInfo(recovered, peoplePackets, shareDataMap,
					relevantSubset, usedHashes, usedMarkerInfo)
				if err != nil {
					log.Fatalln("Things went wrong while trying to get higher secrets")
				}
			}
		}
	}
}

func HierarchicalInDisSecretRecovery(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantHashes [][32]byte, runRelevantMarkerInfo [][]byte,
	runRelevantSalt [32]byte, allLayersRelevantShares *[][]*share.PriShare,
	usedShares *[]*share.PriShare, firstSecretRecovered *bool,
	secretRecovered *bool, recoveredKey *kyber.Scalar) (bool, bool, error) {
	// Check if there is some match based on the metadata
	isHashMatched, isCorrect, _, _, correctX, finalLevelObtained, err :=
		crypto_protocols.GetIndisShareMatch(recovered,
			runRelevantHashes, runRelevantMarkerInfo, runRelevantSalt)
	if err != nil {
		fmt.Println("Hash match value", isHashMatched, "but marker match value",
			isCorrect)
		return isHashMatched, isCorrect, err
	}
	// If there is a match, the check for the higher layers
	if isCorrect {
		correctShare := &share.PriShare{I: correctX, V: recovered}
		if !(*firstSecretRecovered) {
			*firstSecretRecovered = true
			*allLayersRelevantShares = append(*allLayersRelevantShares,
				relevantSubset)
			*allLayersRelevantShares = append(*allLayersRelevantShares,
				[]*share.PriShare{correctShare})
		} else {
			(*allLayersRelevantShares)[0] = append((*allLayersRelevantShares)[0],
				relevantSubset...)
			if !crypto_protocols.CheckSharePresent((*allLayersRelevantShares)[1],
				correctShare) {
				(*allLayersRelevantShares)[1] = append((*allLayersRelevantShares)[1],
					correctShare)
			}
		}
		*usedShares = append(*usedShares, relevantSubset...)
		// If the secret has been recovered, then no need to run the
		// recovery
		if finalLevelObtained {
			*secretRecovered = true
			*recoveredKey = recovered
		} else {
			// Secret recovery for the layers other than the leaves
			for sharesIndex, sharesValue := range *allLayersRelevantShares {
				// No need to recover for the leaves and the layers which have only
				// one share
				if sharesIndex == 0 || len(sharesValue) == 1 {
					continue
				} else {
					// The prefix 'sup' stands for super
					// This is used for the secrets of the higher layers
					supRecovered, err := share.RecoverSecret(g, sharesValue,
						len(sharesValue), len(sharesValue))
					if err != nil {
						fmt.Println(sharesValue)
						log.Fatal(err)
					}
					// Recover the secrets from the upper layer
					_, isSupCorrect, _, _, supCorrectX, supFinalLevelObtained, err :=
						crypto_protocols.GetIndisShareMatch(supRecovered,
							runRelevantHashes,
							runRelevantMarkerInfo, runRelevantSalt)
					if err != nil {
						log.Fatal(err)
					}
					secretLayer := sharesIndex + 1
					if supFinalLevelObtained {
						*secretRecovered = true
						*recoveredKey = supRecovered
						break
					}
					if isSupCorrect {
						supCorrectShare := &share.PriShare{I: supCorrectX,
							V: supRecovered}
						if secretLayer >= len(*allLayersRelevantShares) {
							(*allLayersRelevantShares) = append(*allLayersRelevantShares,
								[]*share.PriShare{supCorrectShare})
						} else {
							(*allLayersRelevantShares)[secretLayer] =
								append((*allLayersRelevantShares)[secretLayer],
									supCorrectShare)
						}
					}
				}
			}
		}
	}
	return isHashMatched, isCorrect, nil
}

func UpdateUsedInfo(recovered kyber.Scalar, peoplePackets []Packet,
	shareDataMap map[*share.PriShare]int, relevantSubset []*share.PriShare,
	usedHashes *[][32]byte, usedMarkerInfo *[][]byte) error {
	for i := 1; i < len(relevantSubset); i++ {
		// fmt.Println("chakchak", i)
		otherRelevantHashes := peoplePackets[shareDataMap[relevantSubset[i]]].RelevantHashes
		otherRelevantMarkerInfo := peoplePackets[shareDataMap[relevantSubset[i]]].MarkerInfo
		otherRelevantSalt := peoplePackets[shareDataMap[relevantSubset[i]]].Salt
		// fmt.Println("Things ran in", i)
		// isMatched1, isMatched2, correctHash, correctMarkerInfo, _, _, err := crypto_protocols.GetIndisShareMatch(recovered,
		// 	otherRelevantHashes, otherRelevantMarkerInfo, otherRelevantSalt)
		isMatched1, isMatched2, _, _, _, _, err := crypto_protocols.GetIndisShareMatch(recovered,
			otherRelevantHashes, otherRelevantMarkerInfo, otherRelevantSalt)
		if err != nil {
			fmt.Println("Update info function", isMatched1, isMatched2)
			fmt.Println(relevantSubset[i])
			fmt.Println(otherRelevantMarkerInfo)
			return err
		}
		// if isMatched1 {
		// 	(*usedHashes) = append((*usedHashes), correctHash)
		// }
		// if isMatched2 {
		// 	(*usedMarkerInfo) = append((*usedMarkerInfo), correctMarkerInfo)
		// }
	}
	return nil
}
