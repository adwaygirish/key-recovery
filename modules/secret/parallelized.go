package secret

import (
	"crypto/cipher"
	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	"log"
	"sync"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func AdditiveOptUsedIndisSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
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
		var peoplePackets []AdditivePacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelizedUint16(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelizedUint16(g *edwards25519.SuiteEd25519,
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
	var relevantIndices []uint16
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i]] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, uint16(i))
		}
	}

	shareIndicesSet := utils.GenerateIndicesSetUint16(len(relevantShareData))

	relevantIndicesSubsets := utils.GenerateSubsetsOfSizeUint16Filtered(shareIndicesSet, absoluteThreshold, relevantIndices)

	// Get the required number of routines
	noOfSubsets := len(relevantIndicesSubsets) / absoluteThreshold
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
	var smallerSubsets [][]uint16
	for i := 0; i < noOfRoutines; i++ {
		if i == (noOfRoutines - 1) {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*absoluteThreshold:])
		} else {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*absoluteThreshold:(i+1)*perSubsetLen*absoluteThreshold])
		}
	}

	usedSharesChannel := make(chan []*share.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		go ComputeCombinationsAdditiveUint16(g, smallerSubsets[i], relevantShareData,
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

func ComputeCombinationsAdditiveUint16(g *edwards25519.SuiteEd25519,
	relevantIndicesSubsets []uint16,
	relevantShareData []*share.PriShare,
	peoplePackets []AdditivePacket,
	shareDataMap map[*share.PriShare]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []*share.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for i := 0; i < len(relevantIndicesSubsets)/absoluteThreshold; i++ {
		indicesSet := relevantIndicesSubsets[i*absoluteThreshold : (i+1)*absoluteThreshold]
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

func LeavesAdditiveOptUsedIndisRecoveryParallellized(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte) (bool, [32]byte, error) {
	isHashMatched, matchedHash, err := crypto_protocols.GetAdditiveIndisShareMatch(
		recovered, runRelevantHashes, runRelevantSalt)
	if err != nil {
		log.Fatalln(err)
		return false, matchedHash, err
	}
	return isHashMatched, matchedHash, nil
}

// **************************************************************************
// **************************************************************************

// ************Functions for basic***************
// **************************************************************************

func BasicHashedSecretRecoveryParallelizedUint16(g *edwards25519.SuiteEd25519,
	anonymitySet []*share.PriShare, accessOrder []int,
	secretKeyHash [32]byte) (kyber.Scalar, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	var recovered kyber.Scalar
	var isRecovered bool
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		var indicesSet []uint16
		for _, el := range accessOrder[:obtainedLength] {
			indicesSet = append(indicesSet, uint16(el))
		}
		// The combinations with the share of the most recently contacted
		// person is relevant
		relevantIndex := accessOrder[obtainedLength-1]
		// The user tries different thresholds
		for threshold := 2; threshold <= obtainedLength; threshold++ {
			// Generate different combinations of the secret shares
			// Generate combinations without the last obtained share
			relevantIndicesSubsets :=
				utils.GenerateSubsetsOfSizeUint16(indicesSet[:obtainedLength-1], threshold-1)

			// Get the required number of routines
			noOfSubsets := len(relevantIndicesSubsets) / (threshold - 1)
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
			var smallerSubsets [][]uint16
			for i := 0; i < noOfRoutines; i++ {
				if i == (noOfRoutines - 1) {
					smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*(threshold-1):])
				} else {
					smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*(threshold-1):(i+1)*perSubsetLen*(threshold-1)])
				}
			}

			recoveredChannel := make(chan kyber.Scalar, noOfRoutines)
			var wg sync.WaitGroup
			// For each subset, run it in a separate subroutine
			for i := 0; i < noOfRoutines; i++ {
				wg.Add(1)
				go ComputeCombinationsBasicUint16(g, smallerSubsets[i], anonymitySet,
					relevantIndex, threshold-1, secretKeyHash, recoveredChannel, &wg)
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

func ComputeCombinationsBasicUint16(g *edwards25519.SuiteEd25519,
	thresholdIndicesSubsets []uint16,
	anonymitySet []*share.PriShare,
	relevantIndex int,
	subThreshold int,
	secretKeyHash [32]byte,
	recoveredChannel chan<- kyber.Scalar,
	wg *sync.WaitGroup) {
	defer wg.Done()
	// Try different combinations for recovery
	for i := 0; i < len(thresholdIndicesSubsets)/subThreshold; i++ {
		relevantIndices := thresholdIndicesSubsets[i*subThreshold : (i+1)*subThreshold]
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

// **************************************************************************
// **************************************************************************

// ************Functions for thresholded***************
// **************************************************************************

func ThOptUsedIndisSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
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
		PersonwiseThOptUsedIndisSecretRecoveryParallelizedUint16(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseThOptUsedIndisSecretRecoveryParallelizedUint16(g *edwards25519.SuiteEd25519,
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
	var relevantIndices []uint16
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i]] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, uint16(i))
		}
	}
	shareIndicesSet := utils.GenerateIndicesSetUint16(len(relevantShareData))

	relevantIndicesSubsets := utils.GenerateSubsetsOfSizeUint16Filtered(shareIndicesSet, absoluteThreshold, relevantIndices)

	// Get the required number of routines
	noOfSubsets := len(relevantIndicesSubsets) / absoluteThreshold
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
	var smallerSubsets [][]uint16
	for i := 0; i < noOfRoutines; i++ {
		if i == (noOfRoutines - 1) {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*absoluteThreshold:])
		} else {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*absoluteThreshold:(i+1)*perSubsetLen*absoluteThreshold])
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
		go ComputeCombinationsThresholdedUint16(g, smallerSubsets[i], relevantShareData,
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

func ComputeCombinationsThresholdedUint16(g *edwards25519.SuiteEd25519,
	relevantIndicesSubsets []uint16,
	relevantShareData []*share.PriShare,
	peoplePackets []ThresholdedPacket,
	shareDataMap map[*share.PriShare]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []*share.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for i := 0; i < len(relevantIndicesSubsets)/absoluteThreshold; i++ {
		indicesSet := relevantIndicesSubsets[i*absoluteThreshold : (i+1)*absoluteThreshold]
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

func LeavesThresholdedOptUsedIndisRecoveryParallelized(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte) (bool, int, error) {
	isEncryptionMatched, correctX, _, err := crypto_protocols.GetThresholdedIndisShareMatch(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
		return isEncryptionMatched, -1, err
	}
	return isEncryptionMatched, correctX, nil
}

// **************************************************************************
// **************************************************************************

// ************Functions for hinted***************
// **************************************************************************

func HintedTOptUsedIndisSecretRecoveryParallelized(g *edwards25519.SuiteEd25519,
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
		PersonwiseHintedTOptUsedIndisSecretRecoveryParallelizedUint16(g, randSeedShares, peoplePackets,
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

func PersonwiseHintedTOptUsedIndisSecretRecoveryParallelizedUint16(g *edwards25519.SuiteEd25519,
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
	var relevantIndices []uint16
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i]] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, uint16(i))
		}
	}
	shareIndicesSet := utils.GenerateIndicesSetUint16(len(relevantShareData))

	relevantIndicesSubsets := utils.GenerateSubsetsOfSizeUint16Filtered(shareIndicesSet, absoluteThreshold, relevantIndices)

	// Get the required number of routines
	noOfSubsets := len(relevantIndicesSubsets) / absoluteThreshold
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
	var smallerSubsets [][]uint16
	for i := 0; i < noOfRoutines; i++ {
		if i == (noOfRoutines - 1) {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*absoluteThreshold:])
		} else {
			smallerSubsets = append(smallerSubsets, relevantIndicesSubsets[i*perSubsetLen*absoluteThreshold:(i+1)*perSubsetLen*absoluteThreshold])
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
		go ComputeCombinationsHintedTUint16(g, smallerSubsets[i], relevantShareData,
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

func ComputeCombinationsHintedTUint16(g *edwards25519.SuiteEd25519,
	relevantIndicesSubsets []uint16,
	relevantShareData []*share.PriShare,
	peoplePackets []HintedTPacket,
	shareDataMap map[*share.PriShare]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []*share.PriShare,
	hintedPeopleChannel chan<- int, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]*share.PriShare, absoluteThreshold)
	for i := 0; i < len(relevantIndicesSubsets)/absoluteThreshold; i++ {
		indicesSet := relevantIndicesSubsets[i*absoluteThreshold : (i+1)*absoluteThreshold]
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

func LeavesHintedTOptUsedIndisRecoveryParallelized(g *edwards25519.SuiteEd25519,
	recovered kyber.Scalar, relevantSubset []*share.PriShare,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte) (bool, int, error) {
	isEncryptionMatched, hint, _, err := crypto_protocols.GetThresholdedIndisShareMatch(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
		return isEncryptionMatched, -1, err
	}
	return isEncryptionMatched, hint, nil
}

func UpdateHints(packet HintedTPacket, recovered kyber.Scalar,
	hintedTrustees *[]int) {
	runRelevantEncryptions := packet.RelevantEncryptions
	runRelevantNonce := packet.Nonce
	isEncryptionMatched, hint, _, err := crypto_protocols.GetThresholdedIndisShareMatch(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
	}
	if isEncryptionMatched {
		if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, hint) {
			(*hintedTrustees) = append((*hintedTrustees), hint)
		}
	}
}
