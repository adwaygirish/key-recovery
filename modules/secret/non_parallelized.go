package secret

import (
	"crypto/cipher"
	"fmt"
	"log"
	"sync"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func AdditiveOptUsedIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	anonymityPackets []AdditivePacket, accessOrder []int,
	absoluteThreshold int) kyber.Scalar {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	var usedShares [][]*share.PriShare
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
		PersonwiseAdditiveOptUsedIndisSecretRecovery(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseAdditiveOptUsedIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []AdditivePacket, absoluteThreshold int,
	usedShares *[][]*share.PriShare, obtainedSubsecrets *[]kyber.Scalar,
	secretRecovered *bool, recoveredKey *kyber.Scalar) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	var mostRecentPacket AdditivePacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}

	CheckAlreadyObtainedSubsecrets(g, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket)

	// Do not use the shares which have been already used for recovery
	relevantShareData, err := GetRelevantShareData(allShareData,
		usedShares)
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

	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubsets [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubsets = append(relevantIndicesSubsets, indicesSubset)
		}
	}

	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
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
		isHashMatched, _, err := LeavesAdditiveOptUsedIndisRecovery(g,
			recovered, relevantSubset, runRelevantHashes,
			runRelevantSalt, obtainedSubsecrets, usedShares, -1)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isHashMatched && len((*obtainedSubsecrets)) > 1 {
			SubsecretsAdditiveIndisRecovery(g, randSeedShares, runRelevantHashes,
				runRelevantSalt, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func GetRelevantShareData(allShareData []*share.PriShare,
	usedShares *[][]*share.PriShare) ([]*share.PriShare, error) {
	allShareDataCopy := allShareData[:]
	for _, usedShareSet := range *usedShares {
		outputShareSet, err := crypto_protocols.GetSharesSetDifference(allShareDataCopy,
			usedShareSet)
		if err != nil {
			log.Fatalln(err)
			return nil, err
		}
		allShareDataCopy = outputShareSet[:]
	}
	return allShareDataCopy, nil
}

func CheckAlreadyObtainedSubsecrets(g *edwards25519.SuiteEd25519,
	absoluteThreshold int, usedShares *[][]*share.PriShare,
	obtainedSubsecrets *[]kyber.Scalar, mostRecentPacket AdditivePacket) {
	mostRecentShareVals := mostRecentPacket.ShareData
	for _, shareVal := range mostRecentShareVals {
		for index, usedShareSet := range *usedShares {
			var relevantShares []*share.PriShare
			relevantShares = append(relevantShares, shareVal)
			relevantShares = append(relevantShares, usedShareSet[:absoluteThreshold-1]...)
			// Get the recovered secret from the absoluteThreshold number of shares
			recovered, err := share.RecoverSecret(g, relevantShares,
				absoluteThreshold, absoluteThreshold)
			if err != nil {
				fmt.Println(relevantShares)
				log.Fatal(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			runRelevantHashes := mostRecentPacket.RelevantHashes
			runRelevantSalt := mostRecentPacket.Salt
			isHashMatched, _, err := LeavesAdditiveOptUsedIndisRecovery(g,
				recovered, relevantShares, runRelevantHashes,
				runRelevantSalt, obtainedSubsecrets, usedShares, index)
			if err != nil {
				log.Fatalln(err)
				return
			}
			if isHashMatched {
				break
			}
		}
	}
}

func LeavesAdditiveOptUsedIndisRecovery(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantHashes [][32]byte, runRelevantSalt [32]byte,
	obtainedSubsecrets *[]kyber.Scalar,
	usedShares *[][]*share.PriShare, index int) (bool, [32]byte, error) {
	isHashMatched, matchedHash, err := crypto_protocols.GetAdditiveIndisShareMatch(
		recovered, runRelevantHashes, runRelevantSalt)
	if err != nil {
		log.Fatalln(err)
		return false, matchedHash, err
	}
	if isHashMatched {
		// Index represents the index of the already used set of shares
		// When a match is found with a completely different set,
		// then, index sent is -1
		if index != -1 {
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[index], relevantShare) {
					(*usedShares)[index] = append((*usedShares)[index], relevantShare)
				}
			}
		} else {
			emptyShares := make([]*share.PriShare, 0)
			(*usedShares) = append((*usedShares), emptyShares)
			l := len(*usedShares)
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[l-1], relevantShare) {
					(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
				}
			}
			if !crypto_protocols.CheckSubsecretAlreadyRecovered(*obtainedSubsecrets,
				recovered) {
				*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
			}
		}
	}
	return isHashMatched, matchedHash, nil
}

// TODO: why you need both anonimitySetSize and anonimitySet? Here
// we aren't in C, you can derive the former from the latter
// using the builtin len function (I gave it a try in this function)
// Now you can remove one parameter of the function
func BasicHashedSecretRecovery(g kyber.Group,
	anonymitySet []*share.PriShare, accessOrder []int,
	secretKeyHash [32]byte) (kyber.Scalar, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		// fmt.Println("Current person number", obtainedLength)
		indicesSet := accessOrder[:obtainedLength]
		relevantIndex := accessOrder[obtainedLength-1]
		// The user tries different thresholds
		for threshold := 2; threshold <= obtainedLength; threshold++ {
			// Generate different combinations of the secret shares
			// Generate combinations without the last obtained share
			thresholdIndicesSubsets :=
				utils.GenerateSubsetsOfSize(indicesSet[:obtainedLength-1], threshold-1)
			// Try different combinations for recovery
			for _, relevantIndices := range thresholdIndicesSubsets {
				relevantSubset := make([]*share.PriShare, 0, len(relevantIndices))
				for _, ind := range relevantIndices {
					relevantSubset = append(relevantSubset, anonymitySet[ind])
				}
				relevantSubset = append(relevantSubset, anonymitySet[relevantIndex])
				recovered, err := share.RecoverSecret(g, relevantSubset,
					threshold, len(relevantSubset))
				if err != nil {
					// TODO: log.Fatal immediately exit, so the return after it
					// is useless
					log.Fatal(err)
				}
				if crypto_protocols.CheckRecSecretKey(secretKeyHash,
					recovered) {
					return recovered, nil
				}
			}
		}
	}
	return nil, errors.ErrSecretNotFound
}

// This function is meant to work for
// Since the time taken is exponential for the larger thresholds,
// we break the shares into smaller pieces and distribute it among people
// This function does not use any additional information during the
// recovery - that is the user only hashes and the anonymity set
func ThOptUsedIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	anonymityPackets []ThresholdedPacket, accessOrder []int,
	absoluteThreshold int) kyber.Scalar {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	var usedShares [][]*share.PriShare
	var obtainedSubsecrets []*share.PriShare
	var recoveredKey kyber.Scalar
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		var peoplePackets []ThresholdedPacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		PersonwiseThOptUsedIndisSecretRecovery(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseThOptUsedIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []ThresholdedPacket, absoluteThreshold int,
	usedShares *[][]*share.PriShare, obtainedSubsecrets *[]*share.PriShare,
	secretRecovered *bool, recoveredKey *kyber.Scalar) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	var mostRecentPacket ThresholdedPacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}

	CheckAlreadyObtainedThresholdedSubsecrets(g, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket)
	// Do not use the shares which have been already used for recovery
	relevantShareData, err := GetRelevantShareData(allShareData,
		usedShares)
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

	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubsets [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubsets = append(relevantIndicesSubsets, indicesSubset)
		}
	}

	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		// Get the recovered secret from the absoluteThreshold number of shares
		recovered, err := share.RecoverSecret(g, relevantSubset,
			absoluteThreshold, absoluteThreshold)
		if err != nil {
			fmt.Println(relevantSubset)
			log.Fatal(err)
		}
		// Considering the hashes and marker info of only one person in
		// the subset is enough
		runRelevantEncryptions := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantEncryptions
		runRelevantNonce := peoplePackets[shareDataMap[relevantSubset[0]]].Nonce
		isEncryptionMatched, _, err := LeavesThresholdedOptUsedIndisRecovery(g,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce, obtainedSubsecrets, usedShares, -1)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched && len((*obtainedSubsecrets)) > 1 {
			SubsecretsThresholdedIndisRecovery(g, randSeedShares, runRelevantEncryptions,
				runRelevantNonce, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func CheckAlreadyObtainedThresholdedSubsecrets(g *edwards25519.SuiteEd25519,
	absoluteThreshold int, usedShares *[][]*share.PriShare,
	obtainedSubsecrets *[]*share.PriShare, mostRecentPacket ThresholdedPacket) {
	mostRecentShareVals := mostRecentPacket.ShareData
	for _, shareVal := range mostRecentShareVals {
		for index, usedShareSet := range *usedShares {
			var relevantShares []*share.PriShare
			relevantShares = append(relevantShares, shareVal)
			relevantShares = append(relevantShares, usedShareSet[:absoluteThreshold-1]...)
			// Get the recovered secret from the absoluteThreshold number of shares
			recovered, err := share.RecoverSecret(g, relevantShares,
				absoluteThreshold, absoluteThreshold)
			if err != nil {
				fmt.Println(relevantShares)
				log.Fatal(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			runRelevantEncryptions := mostRecentPacket.RelevantEncryptions
			runRelevantNonce := mostRecentPacket.Nonce
			isHashMatched, _, err := LeavesThresholdedOptUsedIndisRecovery(g,
				recovered, relevantShares, runRelevantEncryptions,
				runRelevantNonce, obtainedSubsecrets, usedShares, index)
			if err != nil {
				log.Fatalln(err)
				return
			}
			if isHashMatched {
				break
			}
		}
	}
}

func SubsecretsThresholdedIndisRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets []*share.PriShare, secretRecovered *bool,
	recoveredKey *kyber.Scalar) {
	*secretRecovered, *recoveredKey = crypto_protocols.GetThresholdedNoncedSubsecretMatch(g, randSeedShares, runRelevantEncryptions, runRelevantNonce, obtainedSubsecrets)
}

func LeavesThresholdedOptUsedIndisRecovery(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantEncryptions [][]byte, runRelevantNonce [32]byte,
	obtainedSubsecrets *[]*share.PriShare,
	usedShares *[][]*share.PriShare, index int) (bool, []byte, error) {
	isEncryptionMatched, correctX, matchedEncryption, err := crypto_protocols.GetThresholdedIndisShareMatch(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
		return false, matchedEncryption, err
	}
	if isEncryptionMatched {
		// Index represents the index of the already used set of shares
		// When a match is found with a completely different set,
		// then, index sent is -1
		if index != -1 {
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[index], relevantShare) {
					(*usedShares)[index] = append((*usedShares)[index], relevantShare)
				}
			}
		} else {
			emptyShares := make([]*share.PriShare, 0)
			(*usedShares) = append((*usedShares), emptyShares)
			l := len(*usedShares)
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[l-1], relevantShare) {
					(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
				}
			}
			recoveredShare := &share.PriShare{I: correctX, V: recovered}
			if !crypto_protocols.CheckShareAlreadyUsed(*obtainedSubsecrets,
				recoveredShare) {
				*obtainedSubsecrets = append(*obtainedSubsecrets, recoveredShare)
			}
		}
	}
	return isEncryptionMatched, matchedEncryption, nil
}

// This function is meant to work for
// Since the time taken is exponential for the larger thresholds,
// we break the shares into smaller pieces and distribute it among people
// This function does not use any additional information during the
// recovery - that is the user only hashes and the anonymity set
func HintedTOptUsedIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	anonymityPackets []HintedTPacket, accessOrder []int,
	absoluteThreshold int) kyber.Scalar {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	var usedShares [][]*share.PriShare
	var hintedPeople []int
	var obtainedSubsecrets []kyber.Scalar
	var recoveredKey kyber.Scalar
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		var peoplePackets []HintedTPacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		PersonwiseHintedTOptUsedIndisSecretRecovery(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey, &hintedPeople)
		if secretRecovered {
			break
		}
		if len(hintedPeople) != 0 {
			utils.UpdateOrder(hintedPeople, &accessOrder, obtainedLength)
		}
	}
	return recoveredKey
}

func PersonwiseHintedTOptUsedIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []HintedTPacket,
	absoluteThreshold int,
	usedShares *[][]*share.PriShare,
	obtainedSubsecrets *[]kyber.Scalar,
	secretRecovered *bool,
	recoveredKey *kyber.Scalar,
	hintedTrustees *[]int) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	var mostRecentPacket HintedTPacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}

	CheckAlreadyObtainedHintedTSubsecrets(g, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket, hintedTrustees)
	// Do not use the shares which have been already used for recovery
	relevantShareData, err := GetRelevantShareData(allShareData,
		usedShares)
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

	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubsets [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubsets = append(relevantIndicesSubsets, indicesSubset)
		}
	}

	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		// Get the recovered secret from the absoluteThreshold number of shares
		recovered, err := share.RecoverSecret(g, relevantSubset,
			absoluteThreshold, absoluteThreshold)
		if err != nil {
			fmt.Println(relevantSubset)
			log.Fatal(err)
		}
		// Considering the hashes and marker info of only one person in
		// the subset is enough
		runRelevantEncryptions := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantEncryptions
		runRelevantNonce := peoplePackets[shareDataMap[relevantSubset[0]]].Nonce
		isEncryptionMatched, _, err := LeavesHintedTOptUsedIndisRecovery(g,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce, obtainedSubsecrets, usedShares, -1, hintedTrustees)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched && len((*obtainedSubsecrets)) > 1 {
			SubsecretsHintedTIndisRecovery(g, randSeedShares, runRelevantEncryptions,
				runRelevantNonce, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func CheckAlreadyObtainedHintedTSubsecrets(g *edwards25519.SuiteEd25519,
	absoluteThreshold int, usedShares *[][]*share.PriShare,
	obtainedSubsecrets *[]kyber.Scalar, mostRecentPacket HintedTPacket,
	hintedTrustees *[]int) {
	mostRecentShareVals := mostRecentPacket.ShareData
	for _, shareVal := range mostRecentShareVals {
		for index, usedShareSet := range *usedShares {
			var relevantShares []*share.PriShare
			relevantShares = append(relevantShares, shareVal)
			relevantShares = append(relevantShares, usedShareSet[:absoluteThreshold-1]...)
			// Get the recovered secret from the absoluteThreshold number of shares
			recovered, err := share.RecoverSecret(g, relevantShares,
				absoluteThreshold, absoluteThreshold)
			if err != nil {
				fmt.Println(relevantShares)
				log.Fatal(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			runRelevantEncryptions := mostRecentPacket.RelevantEncryptions
			runRelevantNonce := mostRecentPacket.Nonce
			isHashMatched, _, err := LeavesHintedTOptUsedIndisRecovery(g,
				recovered, relevantShares, runRelevantEncryptions,
				runRelevantNonce, obtainedSubsecrets, usedShares, index,
				hintedTrustees)
			if err != nil {
				log.Fatalln(err)
				return
			}
			if isHashMatched {
				break
			}
		}
	}
}

func SubsecretsHintedTIndisRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets []kyber.Scalar, secretRecovered *bool,
	recoveredKey *kyber.Scalar) {
	*secretRecovered, *recoveredKey = crypto_protocols.GetHintedTNoncedSubsecretMatch(g, randSeedShares, runRelevantEncryptions, runRelevantNonce, obtainedSubsecrets, recoveryHint)
}

func LeavesHintedTOptUsedIndisRecovery(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantEncryptions [][]byte, runRelevantNonce [32]byte,
	obtainedSubsecrets *[]kyber.Scalar,
	usedShares *[][]*share.PriShare, index int,
	hintedTrustees *[]int) (bool, []byte, error) {
	// The packet structure is the same as the thresholded model
	// Therefore, we can use the function as is
	isEncryptionMatched, hint, matchedEncryption, err :=
		crypto_protocols.GetThresholdedIndisShareMatch(
			recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
		return false, matchedEncryption, err
	}
	if isEncryptionMatched {
		// Index represents the index of the already used set of shares
		// When a match is found with a completely different set,
		// then, index sent is -1
		if index != -1 {
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[index], relevantShare) {
					(*usedShares)[index] = append((*usedShares)[index], relevantShare)
				}
			}
			if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, hint) {
				(*hintedTrustees) = append((*hintedTrustees), hint)
			}
		} else {
			emptyShares := make([]*share.PriShare, 0)
			(*usedShares) = append((*usedShares), emptyShares)
			l := len(*usedShares)
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[l-1], relevantShare) {
					(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
				}
			}
			// recoveredShare := &share.PriShare{I: correctX, V: recovered}
			if !crypto_protocols.CheckSubsecretAlreadyRecovered(*obtainedSubsecrets,
				recovered) {
				*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
			}
			if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, hint) {
				(*hintedTrustees) = append((*hintedTrustees), hint)
			}
		}
	}
	return isEncryptionMatched, matchedEncryption, nil
}

func ComputeCombinationsHintedT(g *edwards25519.SuiteEd25519,
	relevantIndicesSubsets [][]int,
	relevantShareData []*share.PriShare,
	peoplePackets []HintedTPacket,
	shareDataMap map[*share.PriShare]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []*share.PriShare,
	hintedPeopleChannel chan<- int, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		// Get the recovered secret from the absoluteThreshold number of shares
		recovered, err := share.RecoverSecret(g, relevantSubset,
			absoluteThreshold, absoluteThreshold)
		if err != nil {
			fmt.Println(relevantSubset)
			log.Fatal(err)
		}
		// Considering the hashes and marker info of only one person in
		// the subset is enough
		runRelevantEncryptions := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantEncryptions
		runRelevantNonce := peoplePackets[shareDataMap[relevantSubset[0]]].Nonce
		isEncryptionMatched, hint, err := LeavesHintedTOptUsedIndisRecoveryParallelized(g,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched {
			outputSubset := make([]*share.PriShare, absoluteThreshold)
			copy(outputSubset, relevantSubset)
			usedSharesChannel <- outputSubset
			hintedPeopleChannel <- hint
		}
	}
}

func PersonwiseHintedTOptUsedIndisSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []HintedTPacket,
	absoluteThreshold int,
	usedShares *[][]*share.PriShare,
	obtainedSubsecrets *[]kyber.Scalar,
	secretRecovered *bool,
	recoveredKey *kyber.Scalar,
	hintedTrustees *[]int) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	var mostRecentPacket HintedTPacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}

	CheckAlreadyObtainedHintedTSubsecrets(g, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket, hintedTrustees)
	// Do not use the shares which have been already used for recovery
	relevantShareData, err := GetRelevantShareData(allShareData,
		usedShares)
	if err != nil {
		log.Fatal(err)
	}
	if len(relevantShareData) < absoluteThreshold {
		return
	}

	// The combinations which contain the packets of the most recently
	// contacted person are relevant ones
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i]] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, i)
		}
	}
	shareIndicesSet := utils.GenerateIndicesSet(len(relevantShareData))

	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubsets [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubsets = append(relevantIndicesSubsets, indicesSubset)
		}
	}

	// Get the required number of routines
	noOfSubsets := len(relevantIndicesSubsets)
	// noOfRoutines := 1
	// for key, value := range routinesMap {
	// 	if noOfSubsets >= key {
	// 		noOfRoutines = value
	// 		break
	// 	}
	// }
	noOfRoutines := 16

	// Number of combinations each routine needs to run
	perSubsetLen := noOfSubsets / noOfRoutines
	// Distribute the subsets into smaller slices
	var smallerSubsets [][][]int
	for i := 0; i < noOfRoutines; i++ {
		if i == (noOfRoutines - 1) {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:])
		} else {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:(i+1)*perSubsetLen])
		}
	}

	// Channel for the user shares
	usedSharesChannel := make(chan []*share.PriShare, absoluteThreshold*1000)
	// Channel for the hinted people
	hintedPeopleChannel := make(chan int, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		copySlice := make([]HintedTPacket, len(peoplePackets))
		copy(copySlice, peoplePackets)
		go ComputeCombinationsHintedT(g, smallerSubsets[i], relevantShareData,
			copySlice, shareDataMap, absoluteThreshold, usedSharesChannel,
			hintedPeopleChannel, &wg)
	}

	wg.Wait()

	close(usedSharesChannel)
	close(hintedPeopleChannel)

	for usedShareData := range usedSharesChannel {
		recovered, err := share.RecoverSecret(g, usedShareData,
			absoluteThreshold, absoluteThreshold)
		if err != nil {
			fmt.Println(usedShareData)
			log.Fatal(err)
		}
		emptyShares := make([]*share.PriShare, 0)
		(*usedShares) = append((*usedShares), emptyShares)
		l := len(*usedShares)
		for _, relevantShare := range usedShareData {
			if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[l-1], relevantShare) {
				(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
			}
			relevantPacket := peoplePackets[shareDataMap[relevantShare]]
			UpdateHints(relevantPacket, recovered, hintedTrustees)
		}
		if !crypto_protocols.CheckSubsecretAlreadyRecovered(*obtainedSubsecrets,
			recovered) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
		}
		if len((*obtainedSubsecrets)) > 1 {
			runRelevantEncryptions := peoplePackets[shareDataMap[usedShareData[0]]].RelevantEncryptions
			runRelevantNonce := peoplePackets[shareDataMap[usedShareData[0]]].Nonce
			SubsecretsHintedTIndisRecovery(g, randSeedShares, runRelevantEncryptions,
				runRelevantNonce, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}

	for hint := range hintedPeopleChannel {
		if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, hint) {
			(*hintedTrustees) = append((*hintedTrustees), hint)
		}
	}
}

func ComputeCombinationsThresholded(g *edwards25519.SuiteEd25519,
	relevantIndicesSubsets [][]int,
	relevantShareData []*share.PriShare,
	peoplePackets []ThresholdedPacket,
	shareDataMap map[*share.PriShare]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []*share.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
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
		runRelevantEncryptions := peoplePackets[shareDataMap[relevantSubset[0]]].RelevantEncryptions
		runRelevantNonce := peoplePackets[shareDataMap[relevantSubset[0]]].Nonce
		isEncryptionMatched, correctX, err := LeavesThresholdedOptUsedIndisRecoveryParallelized(g,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched {
			outputSubset := make([]*share.PriShare, absoluteThreshold, absoluteThreshold+1)
			copy(outputSubset, relevantSubset)
			subsecretShare := &share.PriShare{I: correctX, V: recovered}
			outputSubset = append(outputSubset, subsecretShare)
			usedSharesChannel <- outputSubset
		}
	}
}

func PersonwiseThOptUsedIndisSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []ThresholdedPacket, absoluteThreshold int,
	usedShares *[][]*share.PriShare, obtainedSubsecrets *[]*share.PriShare,
	secretRecovered *bool, recoveredKey *kyber.Scalar) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	var mostRecentPacket ThresholdedPacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}

	CheckAlreadyObtainedThresholdedSubsecrets(g, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket)
	// Do not use the shares which have been already used for recovery
	relevantShareData, err := GetRelevantShareData(allShareData,
		usedShares)
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

	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubsets [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubsets = append(relevantIndicesSubsets, indicesSubset)
		}
	}

	// Get the required number of routines
	noOfSubsets := len(relevantIndicesSubsets)
	// noOfRoutines := 1
	// for key, value := range routinesMap {
	// 	if noOfSubsets >= key {
	// 		noOfRoutines = value
	// 		break
	// 	}
	// }
	noOfRoutines := 16

	perSubsetLen := noOfSubsets / noOfRoutines
	// Distribute the subsets into smaller slices
	var smallerSubsets [][][]int
	for i := 0; i < noOfRoutines; i++ {
		if i == (noOfRoutines - 1) {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:])
		} else {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:(i+1)*perSubsetLen])
		}
	}

	usedSharesChannel := make(chan []*share.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		copySlice := make([]ThresholdedPacket, len(peoplePackets))
		copy(copySlice, peoplePackets)
		// copyMap := make(map[*share.PriShare]int)
		// for key, value := range shareDataMap {
		// 	copyMap[key] = value
		// }
		go ComputeCombinationsThresholded(g, smallerSubsets[i], relevantShareData,
			copySlice, shareDataMap, absoluteThreshold, usedSharesChannel, &wg)
	}

	wg.Wait()

	close(usedSharesChannel)

	for usedShareData := range usedSharesChannel {
		recoveredShare := usedShareData[len(usedShareData)-1]
		// Add the shares that have been used for recovery
		emptyShares := make([]*share.PriShare, 0)
		(*usedShares) = append((*usedShares), emptyShares)
		l := len(*usedShares)
		for _, relevantShare := range usedShareData[:len(usedShareData)-1] {
			if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[l-1], relevantShare) {
				(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
			}
		}
		// Add the recovered subsecret
		if !crypto_protocols.CheckShareAlreadyUsed(*obtainedSubsecrets,
			recoveredShare) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recoveredShare)
		}
		// Check if the secret key can be recovered
		if len((*obtainedSubsecrets)) > 1 {
			runRelevantEncryptions := peoplePackets[shareDataMap[usedShareData[0]]].RelevantEncryptions
			runRelevantNonce := peoplePackets[shareDataMap[usedShareData[0]]].Nonce
			SubsecretsThresholdedIndisRecovery(g, randSeedShares, runRelevantEncryptions,
				runRelevantNonce, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

// This function is meant for benchmarking the function
func BasicHashedSecretRecoveryParallelizedAlternate(g *edwards25519.SuiteEd25519,
	anonymitySet []*share.PriShare, accessOrder []int,
	secretKeyHash [32]byte, threshold int) (kyber.Scalar, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	var recovered kyber.Scalar
	var isRecovered bool
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		if threshold > obtainedLength {
			continue
		}
		indicesSet := accessOrder[:obtainedLength]
		// The combinations with the share of the most recently contacted
		// person is relevant
		relevantIndex := accessOrder[obtainedLength-1]
		// Generate different combinations of the secret shares
		// Generate combinations without the last obtained share
		relevantIndicesSubsets :=
			utils.GenerateSubsetsOfSize(indicesSet[:obtainedLength-1], threshold-1)

		// Get the required number of routines
		noOfSubsets := len(relevantIndicesSubsets)
		noOfRoutines := 1
		for key, value := range routinesMap {
			if noOfSubsets >= key {
				noOfRoutines = value
				break
			}
		}

		perSubsetLen := noOfSubsets / noOfRoutines
		// Distribute the subsets into smaller slices
		var smallerSubsets [][][]int
		for i := 0; i < noOfRoutines; i++ {
			if i == (noOfRoutines - 1) {
				smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:])
			} else {
				smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:(i+1)*perSubsetLen])
			}
		}

		recoveredChannel := make(chan kyber.Scalar, noOfRoutines)
		var wg sync.WaitGroup
		// For each subset, run it in a separate subroutine
		for i := 0; i < noOfRoutines; i++ {
			wg.Add(1)
			go ComputeCombinationsBasic(g, smallerSubsets[i], anonymitySet,
				relevantIndex, secretKeyHash, recoveredChannel, &wg)
		}

		wg.Wait()

		close(recoveredChannel)

		for obtainedData := range recoveredChannel {
			recovered = obtainedData
			isRecovered = true
			break
		}
		if isRecovered {
			break
		}

	}
	if isRecovered {
		return recovered, nil
	}
	return nil, errors.ErrSecretNotFound
}

func ComputeCombinationsBasic(g *edwards25519.SuiteEd25519,
	thresholdIndicesSubsets [][]int,
	anonymitySet []*share.PriShare,
	relevantIndex int,
	secretKeyHash [32]byte,
	recoveredChannel chan<- kyber.Scalar,
	wg *sync.WaitGroup) {
	defer wg.Done()
	// Try different combinations for recovery
	for _, relevantIndices := range thresholdIndicesSubsets {
		relevantSubset := make([]*share.PriShare, 0, len(relevantIndices))
		for _, ind := range relevantIndices {
			relevantSubset = append(relevantSubset, anonymitySet[ind])
		}
		relevantSubset = append(relevantSubset, anonymitySet[relevantIndex])
		recovered, err := share.RecoverSecret(g, relevantSubset,
			len(relevantSubset), len(relevantSubset))
		if err != nil {
			// TODO: log.Fatal immediately exit, so the return after it
			// is useless
			log.Fatal(err)
		}
		if crypto_protocols.CheckRecSecretKey(secretKeyHash,
			recovered) {
			recoveredChannel <- recovered
			break
		}
	}
}

func BasicHashedSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
	anonymitySet []*share.PriShare, accessOrder []int,
	secretKeyHash [32]byte) (kyber.Scalar, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	var recovered kyber.Scalar
	var isRecovered bool
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		indicesSet := accessOrder[:obtainedLength]
		// The combinations with the share of the most recently contacted
		// person is relevant
		relevantIndex := accessOrder[obtainedLength-1]
		// The user tries different thresholds
		for threshold := 2; threshold <= obtainedLength; threshold++ {
			// Generate different combinations of the secret shares
			// Generate combinations without the last obtained share
			relevantIndicesSubsets :=
				utils.GenerateSubsetsOfSize(indicesSet[:obtainedLength-1], threshold-1)

			// Get the required number of routines
			noOfSubsets := len(relevantIndicesSubsets)
			noOfRoutines := 1
			for key, value := range routinesMap {
				if noOfSubsets >= key {
					noOfRoutines = value
					break
				}
			}

			perSubsetLen := noOfSubsets / noOfRoutines
			// Distribute the subsets into smaller slices
			var smallerSubsets [][][]int
			for i := 0; i < noOfRoutines; i++ {
				if i == (noOfRoutines - 1) {
					smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:])
				} else {
					smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:(i+1)*perSubsetLen])
				}
			}

			recoveredChannel := make(chan kyber.Scalar, noOfRoutines)
			var wg sync.WaitGroup
			// For each subset, run it in a separate subroutine
			for i := 0; i < noOfRoutines; i++ {
				wg.Add(1)
				go ComputeCombinationsBasic(g, smallerSubsets[i], anonymitySet,
					relevantIndex, secretKeyHash, recoveredChannel, &wg)
			}

			wg.Wait()

			close(recoveredChannel)

			for obtainedData := range recoveredChannel {
				recovered = obtainedData
				isRecovered = true
				break
			}
			if isRecovered {
				break
			}
		}
	}
	if isRecovered {
		return recovered, nil
	}
	return nil, errors.ErrSecretNotFound
}

func ComputeCombinationsAdditive(g *edwards25519.SuiteEd25519,
	relevantIndicesSubsets [][]int,
	relevantShareData []*share.PriShare,
	peoplePackets []AdditivePacket,
	shareDataMap map[*share.PriShare]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []*share.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
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
		isHashMatched, _, err := LeavesAdditiveOptUsedIndisRecoveryParallellized(g,
			recovered, relevantSubset, runRelevantHashes,
			runRelevantSalt)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isHashMatched {
			outputSubset := make([]*share.PriShare, absoluteThreshold)
			copy(outputSubset, relevantSubset)
			usedSharesChannel <- outputSubset
		}
	}
}

func PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	peoplePackets []AdditivePacket, absoluteThreshold int,
	usedShares *[][]*share.PriShare, obtainedSubsecrets *[]kyber.Scalar,
	secretRecovered *bool, recoveredKey *kyber.Scalar) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []*share.PriShare
	var mostRecentPacket AdditivePacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[*share.PriShare]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData)] = i
		}
	}

	CheckAlreadyObtainedSubsecrets(g, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket)

	// Do not use the shares which have been already used for recovery
	relevantShareData, err := GetRelevantShareData(allShareData,
		usedShares)
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

	allIndicesSubset := utils.GenerateSubsetsOfSize(shareIndicesSet, absoluteThreshold)
	var relevantIndicesSubsets [][]int
	for _, indicesSubset := range allIndicesSubset {
		if len(utils.GetIntersection(indicesSubset, relevantIndices)) > 0 {
			relevantIndicesSubsets = append(relevantIndicesSubsets, indicesSubset)
		}
	}

	// Get the required number of routines
	noOfSubsets := len(relevantIndicesSubsets)
	// noOfRoutines := 1
	// for key, value := range routinesMap {
	// 	if noOfSubsets >= key {
	// 		noOfRoutines = value
	// 		break
	// 	}
	// }
	noOfRoutines := 16

	perSubsetLen := noOfSubsets / noOfRoutines
	// Distribute the subsets into smaller slices
	var smallerSubsets [][][]int
	for i := 0; i < noOfRoutines; i++ {
		if i == (noOfRoutines - 1) {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:])
		} else {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen:(i+1)*perSubsetLen])
		}
	}

	usedSharesChannel := make(chan []*share.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		go ComputeCombinationsAdditive(g, smallerSubsets[i], relevantShareData,
			peoplePackets, shareDataMap, absoluteThreshold, usedSharesChannel, &wg)
	}

	wg.Wait()

	close(usedSharesChannel)

	for usedShareData := range usedSharesChannel {
		recovered, err := share.RecoverSecret(g, usedShareData,
			absoluteThreshold, absoluteThreshold)
		if err != nil {
			fmt.Println(usedShareData)
			log.Fatal(err)
		}
		emptyShares := make([]*share.PriShare, 0)
		(*usedShares) = append((*usedShares), emptyShares)
		l := len(*usedShares)
		for _, relevantShare := range usedShareData {
			if !crypto_protocols.CheckShareAlreadyUsed((*usedShares)[l-1], relevantShare) {
				(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
			}
		}
		if !crypto_protocols.CheckSubsecretAlreadyRecovered(*obtainedSubsecrets,
			recovered) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
		}
		if len((*obtainedSubsecrets)) > 1 {
			runRelevantHashes := peoplePackets[shareDataMap[usedShareData[0]]].RelevantHashes
			runRelevantSalt := peoplePackets[shareDataMap[usedShareData[0]]].Salt
			SubsecretsAdditiveIndisRecovery(g, randSeedShares, runRelevantHashes,
				runRelevantSalt, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}
