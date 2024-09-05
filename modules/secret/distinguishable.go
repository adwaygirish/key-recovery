package secret

import (
	"crypto/cipher"
	"fmt"
	"log"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// This function generates shares for the optimized secret recovery
// This function generates full threshold share (t = n)
// The function returns many value which can be revealed to a user
// as she proceeds with the recovery
func GenerateFTOptDisShares(g kyber.Group, t, n int, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, largestShareSetSize int,
	smallestShareSetSize int) (bool, map[[32]byte][]*share.PriShare,
	map[[32]byte]*share.PriShare, map[[32]byte]int, map[[32]byte]int,
	map[[32]byte]int, []*share.PriShare, [][32]byte, [32]byte) {

	// TODO: I think you should define some sort of
	// type or struct or whatever to hold all these
	// data
	// Store the shares in a 2D slice
	// The shares in a particular slice correspond to the same secret
	outputShares := make(map[[32]byte][]*share.PriShare)
	// Store the hashes of the secret for which the shares have been created
	outputSecretHashes := make(map[[32]byte]*share.PriShare)
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

	if t > n {
		return false, outputShares, outputSecretHashes, hashLevels, noOfShares, thresholds, leavesData, outputSecretHashesSlice, secretKeyHash
	}

	// When the threshold is less than 5
	// Simple generate shares of the secret and distribute them
	if n <= 5 {
		tempSecretKeyShare := &share.PriShare{I: 0, V: secretKey}
		shares := GenerateShares(g, n, n, secretKey, randSeedShares)
		// Obtain the hash in []byte
		secretKeyHash := crypto_protocols.GetShareSHA256(tempSecretKeyShare)
		outputShares[secretKeyHash] = shares
		outputSecretHashes[secretKeyHash] = (tempSecretKeyShare)
		outputSecretHashesSlice = append(outputSecretHashesSlice, secretKeyHash)
		hashLevels[secretKeyHash] = 0
		noOfShares[secretKeyHash] = n
		thresholds[secretKeyHash] = n
		leavesData = append(leavesData, shares...)
	} else {
		// When the threshold is greater than 5
		// Go for the hierarchical approach
		noOfLevels, distribution, leavesNumbers := utils.SplitShares(n,
			largestShareSetSize, smallestShareSetSize)

		GenerateDisUpperLayers(g, secretKey, randSeedShares, noOfLevels,
			distribution, outputShares, outputSecretHashes, hashLevels, noOfShares,
			thresholds, &outputSecretHashesSlice, &penultimateShares, &secretKeyHash)
		GenerateDisLeavesLayer(g, randSeedShares, leavesNumbers, noOfLevels,
			outputShares, outputSecretHashes, hashLevels, noOfShares, thresholds,
			&outputSecretHashesSlice, &penultimateShares, &leavesData)
		fmt.Println(leavesNumbers, distribution)
	}
	return true, outputShares, outputSecretHashes, hashLevels, noOfShares, thresholds, leavesData, outputSecretHashesSlice, secretKeyHash
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the layers above the leaves
func GenerateDisUpperLayers(g kyber.Group, secretKey kyber.Scalar,
	randSeedShares cipher.Stream, noOfLevels int, distribution []int,
	outputShares map[[32]byte][]*share.PriShare,
	outputSecretHashes map[[32]byte]*share.PriShare,
	hashLevels map[[32]byte]int, noOfShares map[[32]byte]int, thresholds map[[32]byte]int,
	outputSecretHashesSlice *[][32]byte, penultimateShares *[]*share.PriShare,
	secretKeyHash *[32]byte) {
	// This is just a temporary variable created for the code to run
	tempSecret := &share.PriShare{I: 0, V: secretKey}
	*secretKeyHash = crypto_protocols.GetShareSHA256(tempSecret)
	layerSecrets := []*share.PriShare{(tempSecret)}
	var nextLayerSecrets []*share.PriShare
	for i := 0; i < noOfLevels-1; i++ {
		noOfSharesPerSecret := distribution[i]
		// For now, we consider full threshold
		for _, layerSecret := range layerSecrets {
			shareVals := GenerateShares(g, noOfSharesPerSecret,
				noOfSharesPerSecret, layerSecret.V, randSeedShares)
			layerSecretHash := crypto_protocols.GetShareSHA256(layerSecret)
			outputShares[layerSecretHash] = shareVals
			outputSecretHashes[layerSecretHash] = layerSecret
			*outputSecretHashesSlice = append(*outputSecretHashesSlice,
				layerSecretHash)
			hashLevels[layerSecretHash] = i
			noOfShares[layerSecretHash] = noOfSharesPerSecret
			thresholds[layerSecretHash] = noOfSharesPerSecret
			if i == noOfLevels-2 {
				*penultimateShares = append(*penultimateShares,
					shareVals...)
			}
			nextLayerSecrets = append(nextLayerSecrets, shareVals...)
		}
		layerSecrets = nextLayerSecrets
	}
}

// This function is called by the GenerateFTOptimizedShares for generating
// shares of the leaves layer
// Leaves are distribute among the trustees
func GenerateDisLeavesLayer(g kyber.Group, randSeedShares cipher.Stream,
	leavesNumbers []int, noOfLevels int,
	outputShares map[[32]byte][]*share.PriShare,
	outputSecretHashes map[[32]byte]*share.PriShare,
	hashLevels map[[32]byte]int, noOfShares map[[32]byte]int, thresholds map[[32]byte]int,
	outputSecretHashesSlice *[][32]byte, penultimateShares *[]*share.PriShare,
	leavesData *[]*share.PriShare) {
	for shareIndex, sharesNumber := range leavesNumbers {
		secretVal := (*penultimateShares)[shareIndex]
		layerSecret := secretVal
		shareVals := GenerateShares(g, sharesNumber,
			sharesNumber, layerSecret.V, randSeedShares)
		layerSecretHash := crypto_protocols.GetShareSHA256(layerSecret)
		outputShares[layerSecretHash] = shareVals
		outputSecretHashes[layerSecretHash] = layerSecret
		*outputSecretHashesSlice = append(*outputSecretHashesSlice,
			layerSecretHash)
		hashLevels[layerSecretHash] = noOfLevels - 1
		noOfShares[layerSecretHash] = sharesNumber
		thresholds[layerSecretHash] = sharesNumber
		*leavesData = append(*leavesData, shareVals...)
	}
}

// This function is meant to work for full threshold
// Since the time taken is exponential for the larger thresholds,
// we break the shares into smaller pieces and distribute it among people
// This function does not use any additional information during the
// recovery - that is the user only hashes and the anonymity set
func FTOptDisSecretRecovery(g kyber.Group, t int, n int, anonymitySetSize int,
	anonymitySet []*share.PriShare, accessOrder []int, secretKeyHash [32]byte,
	largestShareSetSize int, hashesSlice [][32]byte) kyber.Scalar {
	secretRecovered := false
	firstSecretRecovered := false
	var recoveredHashes [][32]byte
	var usedShareNums []int
	var allLayersRelevantShares [][]*share.PriShare
	var recoveredKey kyber.Scalar
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		indicesSet := accessOrder[:obtainedLength]
		// Choose the number which is smaller
		largerThreshold := utils.GetSmallerValue(obtainedLength, largestShareSetSize)
		// The user tries different thresholds
		// Any secret or subsecret in the system has less than or equal to 5
		for threshold := 2; threshold <= largerThreshold; threshold++ {
			// Use the shares that have not been used yet for recovery
			var relevantShareNumbers []int
			if firstSecretRecovered {
				relevantShareNumbers = utils.FindDifference(indicesSet,
					usedShareNums)
			} else {
				relevantShareNumbers = make([]int, len(indicesSet))
				copy(relevantShareNumbers, indicesSet)
			}
			// Generate different combinations of the secret shares
			thresholdIndicesSubsets :=
				utils.GenerateSubsetsOfSize(relevantShareNumbers, threshold)
			// Try different combinations for recovery
			for _, relevantIndices := range thresholdIndicesSubsets {
				var relevantSubset []*share.PriShare
				for _, ind := range relevantIndices {
					relevantSubset = append(relevantSubset,
						anonymitySet[ind])
				}
				if !crypto_protocols.CheckCoordinatesEquality(relevantSubset) {
					continue
				}
				recovered, err := share.RecoverSecret(g, relevantSubset,
					len(relevantSubset), len(relevantSubset))
				if err != nil {
					log.Fatal(err)
				}
				HierarchicalDisSecretRecovery(g, recovered, hashesSlice, largestShareSetSize,
					&firstSecretRecovered, relevantSubset, &allLayersRelevantShares,
					&usedShareNums, &recoveredHashes, relevantIndices, secretKeyHash,
					&secretRecovered, &recoveredKey)
				if secretRecovered {
					break
				}
			}
			if secretRecovered {
				break
			}
		}
	}
	return recoveredKey
}

// This function is called by the OptimizedSecretRecovery function whenever
// there is a recovery from a subset in the anonymity set
func HierarchicalDisSecretRecovery(g kyber.Group, recovered kyber.Scalar, hashesSlice [][32]byte,
	largestShareSetSize int, firstSecretRecovered *bool, relevantSubset []*share.PriShare,
	allLayersRelevantShares *[][]*share.PriShare, usedShareNums *[]int,
	recoveredHashes *[][32]byte, relevantIndices []int, secretKeyHash [32]byte,
	secretRecovered *bool, recoveredKey *kyber.Scalar) {
	// This match will occur for hashes just above the leaves
	isCorrect, correctHash, correctShare := crypto_protocols.GetHashMatch(hashesSlice,
		recovered, largestShareSetSize)

	// If the secret recovered matches with one of the secrets
	// then start trying the recovery of various layers
	if isCorrect {
		if !(*firstSecretRecovered) {
			*firstSecretRecovered = true
			*allLayersRelevantShares = append(*allLayersRelevantShares,
				relevantSubset)
			*allLayersRelevantShares = append(*allLayersRelevantShares,
				[]*share.PriShare{correctShare})
		} else {
			(*allLayersRelevantShares)[0] = append((*allLayersRelevantShares)[0],
				relevantSubset...)
			(*allLayersRelevantShares)[1] = append((*allLayersRelevantShares)[1],
				correctShare)
		}
		*usedShareNums = append(*usedShareNums, relevantIndices...)
		*recoveredHashes = append(*recoveredHashes, correctHash)
		if correctHash == secretKeyHash {
			*secretRecovered = true
		}
		// Secret recovery for the layers other than the leaves
		for sharesIndex, sharesValue := range *allLayersRelevantShares {
			// No need to recover for the leaves and the layers which have only
			// one share
			if sharesIndex == 0 || len(sharesValue) == 1 {
				continue
			}
			// The prefix 'sup' stands for super
			// This is used for the secrets of the higher layers
			supRecovered, err := share.RecoverSecret(g, sharesValue,
				len(sharesValue), len(sharesValue))
			if err != nil {
				log.Fatal(err)
			}
			supIsCorrect, supCorrectHash, supCorrectShare :=
				crypto_protocols.GetHashMatch(hashesSlice, supRecovered,
					largestShareSetSize)
			secretLayer := sharesIndex + 1
			// If the secret key has been recovered,
			// then stop the recovery process
			if supCorrectHash == secretKeyHash {
				*secretRecovered = true
				*recoveredKey = supCorrectShare.V
				break
			}
			if supIsCorrect {
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
