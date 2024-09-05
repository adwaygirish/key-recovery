package secret_binary_extension

import (
	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
	"log"
	"sync"
)

// **************************************************************************
// **************************************************************************

// ************Functions for additive***************
// **************************************************************************
func AdditiveOptUsedIndisSecretRecoveryParallelized(f shamir.Field,
	anonymityPackets []AdditivePacket, accessOrder []int,
	absoluteThreshold int) []uint16 {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	var usedShares [][]shamir.PriShare
	var obtainedSubsecrets [][]uint16
	var recoveredKey []uint16
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		f.InitializeTables()
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		var peoplePackets []AdditivePacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelizedUint16(f, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelizedUint16(f shamir.Field,
	peoplePackets []AdditivePacket, absoluteThreshold int,
	usedShares *[][]shamir.PriShare, obtainedSubsecrets *[][]uint16,
	secretRecovered *bool, recoveredKey *[]uint16) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []shamir.PriShare
	var mostRecentPacket AdditivePacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[uint16]int)
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
			shareDataMap[(shareData.X)] = i
		}
	}

	CheckAlreadyObtainedSubsecrets(f, absoluteThreshold, usedShares,
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
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, uint16(i))
		}
	}

	shareIndicesSet := utils.GenerateIndicesSetUint16(len(relevantShareData))

	relevantIndicesSubsets := utils.GenerateSubsetsOfSizeUint16Filtered(shareIndicesSet, absoluteThreshold, relevantIndices)

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

	usedSharesChannel := make(chan []shamir.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		go ComputeCombinationsAdditiveUint16(f, smallerSubsets[i], relevantShareData,
			peoplePackets, shareDataMap, absoluteThreshold, usedSharesChannel, &wg)
	}

	wg.Wait()

	close(usedSharesChannel)

	for usedShareData := range usedSharesChannel {
		recovered, err := f.CombineUniqueX(usedShareData)
		if err != nil {
			fmt.Println(usedShareData)
			log.Fatal(err)
		}
		emptyShares := make([]shamir.PriShare, 0)
		(*usedShares) = append((*usedShares), emptyShares)
		l := len(*usedShares)
		for _, relevantShare := range usedShareData {
			if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[l-1], relevantShare) {
				(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
			}
		}
		if !crypto_protocols.CheckSubsecretAlreadyRecoveredBinExt(*obtainedSubsecrets,
			recovered) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
		}
		if len((*obtainedSubsecrets)) > 1 {
			runRelevantHashes := peoplePackets[shareDataMap[usedShareData[0].X]].RelevantHashes
			runRelevantSalt := peoplePackets[shareDataMap[usedShareData[0].X]].Salt
			SubsecretsAdditiveIndisRecovery(runRelevantHashes,
				runRelevantSalt, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func ComputeCombinationsAdditiveUint16(f shamir.Field,
	relevantIndicesSubsets []uint16,
	relevantShareData []shamir.PriShare,
	peoplePackets []AdditivePacket,
	shareDataMap map[uint16]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []shamir.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for i := 0; i < len(relevantIndicesSubsets)/absoluteThreshold; i++ {
		indicesSet := relevantIndicesSubsets[i*absoluteThreshold : (i+1)*absoluteThreshold]
		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		recovered, err := f.CombineUniqueX(relevantSubset)
		if err != nil {
			fmt.Println(relevantSubset, indicesSet)
			log.Fatal(err)
		}
		runRelevantHashes := peoplePackets[shareDataMap[relevantSubset[0].X]].RelevantHashes
		runRelevantSalt := peoplePackets[shareDataMap[relevantSubset[0].X]].Salt
		isHashMatched, _, err := LeavesAdditiveOptUsedIndisRecoveryParallelized(f,
			recovered, relevantSubset, runRelevantHashes,
			runRelevantSalt)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isHashMatched {
			outputSubset := make([]shamir.PriShare, absoluteThreshold)
			copy(outputSubset, relevantSubset)
			usedSharesChannel <- outputSubset
		}
	}
}

func LeavesAdditiveOptUsedIndisRecoveryParallelized(f shamir.Field,
	recovered []uint16, relevantSubset []shamir.PriShare,
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte) (bool, [32]byte, error) {
	isHashMatched, matchedHash, err := crypto_protocols.GetAdditiveIndisShareMatchBinExt(
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

func BasicHashedSecretRecoveryParallelizedUint16(f shamir.Field,
	anonymitySet []shamir.PriShare, accessOrder []int,
	secretKeyHash [32]byte) ([]uint16, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	var recovered []uint16
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

			recoveredChannel := make(chan []uint16, 1000)
			var wg sync.WaitGroup
			// For each subset, run it in a separate subroutine
			for i := 0; i < noOfRoutines; i++ {
				wg.Add(1)
				go ComputeCombinationsBasicUint16(f, smallerSubsets[i], anonymitySet,
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

// This function is meant for benchmarking the function

func ComputeCombinationsBasicUint16(f shamir.Field,
	thresholdIndicesSubsets []uint16,
	anonymitySet []shamir.PriShare,
	relevantIndex int,
	subThreshold int,
	secretKeyHash [32]byte,
	recoveredChannel chan<- []uint16,
	wg *sync.WaitGroup) {
	defer wg.Done()
	// Try different combinations for recovery
	for i := 0; i < len(thresholdIndicesSubsets)/subThreshold; i++ {
		relevantIndices := thresholdIndicesSubsets[i*subThreshold : (i+1)*subThreshold]
		relevantSubset := make([]shamir.PriShare, 0, len(relevantIndices))
		for _, ind := range relevantIndices {
			relevantSubset = append(relevantSubset, anonymitySet[ind])
		}
		relevantSubset = append(relevantSubset, anonymitySet[relevantIndex])
		recovered, err := f.CombineUniqueX(relevantSubset)
		if err != nil {
			// TODO: log.Fatal immediately exit, so the return after it
			// is useless
			log.Fatal(err)
		}
		if crypto_protocols.CheckHashesEqual(secretKeyHash,
			crypto_protocols.GetSHA256(shamir.Uint16sToBytes(recovered))) {
			recoveredChannel <- recovered
			break
		}
	}
}

// **************************************************************************
// **************************************************************************

// ************Functions for thresholded***************
// **************************************************************************
func ThOptUsedIndisSecretRecoveryParallelized(f shamir.Field,
	anonymityPackets []ThresholdedPacket, accessOrder []int,
	absoluteThreshold int) [][]uint16 {
	anonymitySetSize := len(anonymityPackets)
	var usedShares [][][]shamir.PriShare
	var obtainedSubsecrets [][]shamir.PriShare
	emptySubKey := make([]uint16, len(anonymityPackets[0].ShareData[0][0].Y))
	recoveredKey := make([][]uint16, len(anonymityPackets[0].ShareData))
	for i := 0; i < len(anonymityPackets[0].ShareData); i++ {
		copy(recoveredKey[i], emptySubKey)
	}
	var secretRecovered []bool
	var recoveredSubKey []uint16
	var trusteesApproached []int
	for i := 0; i < len(anonymityPackets[0].ShareData); i++ {
		usedShares = append(usedShares, [][]shamir.PriShare{})
		obtainedSubsecrets = append(obtainedSubsecrets, []shamir.PriShare{})
		secretRecovered = append(secretRecovered, false)
	}
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	// First of all, recover the first part of the secret
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		f.InitializeTables()
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		var peoplePackets []ThresholdedPacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		for ind1 := 0; ind1 < len(anonymityPackets[0].ShareData); ind1++ {
			if !secretRecovered[ind1] {
				PersonwiseThOptUsedIndisSecretRecoveryParallelizedUint16(f, peoplePackets,
					absoluteThreshold, &(usedShares[ind1]), &(obtainedSubsecrets[ind1]),
					&(secretRecovered[ind1]), &recoveredSubKey, &trusteesApproached, ind1)

				if secretRecovered[ind1] {
					recoveredKey[ind1] = recoveredSubKey
				}
			}
			if utils.AllTrue(secretRecovered) {
				break
			}
		}
	}

	return recoveredKey
}

func PersonwiseThOptUsedIndisSecretRecoveryParallelizedUint16(f shamir.Field,
	peoplePackets []ThresholdedPacket, absoluteThreshold int,
	usedShares *[][]shamir.PriShare, obtainedSubsecrets *[]shamir.PriShare,
	secretRecovered *bool, recoveredKey *[]uint16,
	trusteesApproached *[]int, secretIndex int) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []shamir.PriShare
	var mostRecentPacket ThresholdedPacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[uint16]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData[secretIndex]...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData[secretIndex] {
			shareDataMap[(shareData.X)] = i
		}
	}

	isMatched1 := CheckAlreadyObtainedThresholdedSubsecrets(f, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket, secretIndex)
	if isMatched1 {
		if !utils.IsInSlice((*trusteesApproached), len(peoplePackets)-1) {
			(*trusteesApproached) = append((*trusteesApproached), len(peoplePackets)-1)
		}
	}
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
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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

	usedSharesChannel := make(chan []shamir.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		copySlice := make([]ThresholdedPacket, len(peoplePackets))
		copy(copySlice, peoplePackets)
		go ComputeCombinationsThresholdedUint16(f, smallerSubsets[i], relevantShareData,
			copySlice, shareDataMap, absoluteThreshold, secretIndex, usedSharesChannel, &wg)
	}

	wg.Wait()

	close(usedSharesChannel)

	for usedShareData := range usedSharesChannel {
		recoveredShare := usedShareData[len(usedShareData)-1]
		// Add the shares that have been used for recovery
		emptyShares := make([]shamir.PriShare, 0)
		(*usedShares) = append((*usedShares), emptyShares)
		l := len(*usedShares)
		for _, relevantShare := range usedShareData[:len(usedShareData)-1] {
			if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[l-1], relevantShare) {
				(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
			}
		}
		for _, val := range usedShareData[:len(usedShareData)-1] {
			if !utils.IsInSlice((*trusteesApproached), shareDataMap[val.X]) {
				(*trusteesApproached) = append((*trusteesApproached), shareDataMap[val.X])
			}
		}
		// Add the recovered subsecret
		if !crypto_protocols.CheckShareAlreadyUsedBinExt(*obtainedSubsecrets,
			recoveredShare) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recoveredShare)
		}
		// Check if the secret key can be recovered
		if len((*obtainedSubsecrets)) > 1 {
			runRelevantEncryptions := peoplePackets[shareDataMap[usedShareData[0].X]].RelevantEncryptions[secretIndex]
			runRelevantNonce := peoplePackets[shareDataMap[usedShareData[0].X]].Nonce
			SubsecretsThresholdedIndisRecovery(f, runRelevantEncryptions,
				runRelevantNonce, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func ComputeCombinationsThresholdedUint16(f shamir.Field,
	relevantIndicesSubsets []uint16,
	relevantShareData []shamir.PriShare,
	peoplePackets []ThresholdedPacket,
	shareDataMap map[uint16]int,
	absoluteThreshold int,
	secretIndex int,
	usedSharesChannel chan<- []shamir.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for i := 0; i < len(relevantIndicesSubsets)/absoluteThreshold; i++ {
		indicesSet := relevantIndicesSubsets[i*absoluteThreshold : (i+1)*absoluteThreshold]
		// Create the subset for running the recovery
		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		// Get the recovered secret from the absoluteThreshold number of shares
		recovered, err := f.CombineUniqueX(relevantSubset)
		if err != nil {
			fmt.Println(relevantSubset, indicesSet)
			log.Fatal(err)
		}
		// Considering the hashes and marker info of only one person in
		// the subset is enough
		runRelevantEncryptions := peoplePackets[shareDataMap[relevantSubset[0].X]].RelevantEncryptions[secretIndex]
		runRelevantNonce := peoplePackets[shareDataMap[relevantSubset[0].X]].Nonce
		isEncryptionMatched, correctX, err := LeavesThresholdedOptUsedIndisRecoveryParallelized(f,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched {
			outputSubset := make([]shamir.PriShare, absoluteThreshold, absoluteThreshold+1)
			copy(outputSubset, relevantSubset)
			subsecretShare := shamir.PriShare{X: correctX, Y: recovered}
			outputSubset = append(outputSubset, subsecretShare)
			usedSharesChannel <- outputSubset
		}
	}
}

func LeavesThresholdedOptUsedIndisRecoveryParallelized(f shamir.Field,
	recovered []uint16, relevantSubset []shamir.PriShare,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte) (bool, uint16, error) {
	isEncryptionMatched, correctX, _, err := crypto_protocols.GetThresholdedIndisShareMatchBinExt(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
		return isEncryptionMatched, 0, err
	}
	return isEncryptionMatched, correctX, nil
}

// **************************************************************************
// **************************************************************************

// ************Functions for hinted***************
// **************************************************************************
func HintedTOptUsedIndisSecretRecoveryParallelized(f shamir.Field,
	anonymityPackets []HintedTPacket, accessOrder []int,
	absoluteThreshold int) [][]uint16 {
	anonymitySetSize := len(anonymityPackets)
	var usedShares [][][]shamir.PriShare
	var hintedTrustees []int
	var obtainedSubsecrets [][][]uint16
	emptySubKey := make([]uint16, len(anonymityPackets[0].ShareData[0][0].Y))
	recoveredKey := make([][]uint16, len(anonymityPackets[0].ShareData))
	for i := 0; i < len(anonymityPackets[0].ShareData); i++ {
		copy(recoveredKey[i], emptySubKey)
	}
	var recoveredSubKey []uint16
	var secretRecovered []bool
	for i := 0; i < len(anonymityPackets[0].ShareData); i++ {
		usedShares = append(usedShares, [][]shamir.PriShare{})
		obtainedSubsecrets = append(obtainedSubsecrets, [][]uint16{})
		secretRecovered = append(secretRecovered, false)
	}
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		f.InitializeTables()
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		var peoplePackets []HintedTPacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex])
		}
		for ind1 := 0; ind1 < len(anonymityPackets[0].ShareData); ind1++ {
			if !secretRecovered[ind1] {
				PersonwiseHintedTOptUsedIndisSecretRecoveryParallelizedUint16(f, peoplePackets,
					absoluteThreshold, &(usedShares[ind1]), &(obtainedSubsecrets[ind1]),
					&(secretRecovered[ind1]), &recoveredSubKey,
					ind1, &hintedTrustees)

				if secretRecovered[ind1] {
					recoveredKey[ind1] = recoveredSubKey
				}
			}
			if utils.AllTrue(secretRecovered) {
				break
			}
		}
		if len(hintedTrustees) != 0 {
			utils.UpdateOrderBinExt(hintedTrustees, &accessOrder, obtainedLength)
		}
	}
	return recoveredKey
}

func PersonwiseHintedTOptUsedIndisSecretRecoveryParallelizedUint16(f shamir.Field,
	peoplePackets []HintedTPacket, absoluteThreshold int,
	usedShares *[][]shamir.PriShare, obtainedSubsecrets *[][]uint16,
	secretRecovered *bool, recoveredKey *[]uint16,
	secretIndex int, hintedTrustees *[]int) {
	// Put all the share data into a slice
	var allShareData, relevantShareData []shamir.PriShare
	var mostRecentPacket HintedTPacket
	// Store which shareData corresponds to which person
	shareDataMap := make(map[uint16]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData[secretIndex]...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		if i == len(peoplePackets)-1 {
			mostRecentPacket = peoplePacket
		}
		for _, shareData := range peoplePacket.ShareData[secretIndex] {
			shareDataMap[(shareData.X)] = i
		}
	}

	CheckAlreadyObtainedHintedTSubsecrets(f, absoluteThreshold, usedShares,
		obtainedSubsecrets, mostRecentPacket, secretIndex, hintedTrustees)
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
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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
	usedSharesChannel := make(chan []shamir.PriShare, absoluteThreshold*1000)
	// Channel for the hinted people
	hintedPeopleChannel := make(chan uint16, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		copySlice := make([]HintedTPacket, len(peoplePackets))
		copy(copySlice, peoplePackets)
		go ComputeCombinationsHintedTUint16(f, smallerSubsets[i], relevantShareData,
			copySlice, shareDataMap, absoluteThreshold,
			secretIndex, usedSharesChannel,
			hintedPeopleChannel, &wg)
	}

	wg.Wait()

	close(usedSharesChannel)
	close(hintedPeopleChannel)

	for usedShareData := range usedSharesChannel {
		recovered, err := f.CombineUniqueX(usedShareData)
		if err != nil {
			fmt.Println(usedShareData)
			log.Fatal(err)
		}
		emptyShares := make([]shamir.PriShare, 0)
		(*usedShares) = append((*usedShares), emptyShares)
		l := len(*usedShares)
		for _, relevantShare := range usedShareData {
			if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[l-1], relevantShare) {
				(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
			}
			relevantPacket := peoplePackets[shareDataMap[relevantShare.X]]
			UpdateHints(relevantPacket, recovered, hintedTrustees, secretIndex)
		}
		if !crypto_protocols.CheckSubsecretAlreadyRecoveredBinExt(*obtainedSubsecrets,
			recovered) {
			*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
		}
		if len((*obtainedSubsecrets)) > 1 {
			runRelevantEncryptions := peoplePackets[shareDataMap[usedShareData[0].X]].RelevantEncryptions[secretIndex]
			runRelevantNonce := peoplePackets[shareDataMap[usedShareData[0].X]].Nonce
			SubsecretsHintedTIndisRecovery(runRelevantEncryptions,
				runRelevantNonce, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func ComputeCombinationsHintedT(f shamir.Field,
	relevantIndicesSubsets [][]int,
	relevantShareData []shamir.PriShare,
	peoplePackets []HintedTPacket,
	shareDataMap map[uint16]int,
	absoluteThreshold int,
	secretIndex int,
	usedSharesChannel chan<- []shamir.PriShare,
	hintedPeopleChannel chan<- uint16, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
		for iVal, index := range indicesSet {
			relevantSubset[iVal] = relevantShareData[index]
		}
		// Get the recovered secret from the absoluteThreshold number of shares
		recovered, err := f.CombineUniqueX(relevantSubset)
		if err != nil {
			fmt.Println(relevantSubset)
			log.Fatal(err)
		}
		// Considering the hashes and marker info of only one person in
		// the subset is enough
		runRelevantEncryptions := peoplePackets[shareDataMap[relevantSubset[0].X]].RelevantEncryptions[secretIndex]
		runRelevantNonce := peoplePackets[shareDataMap[relevantSubset[0].X]].Nonce
		isEncryptionMatched, hint, err := LeavesHintedTOptUsedIndisRecoveryParallelized(f,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched {
			outputSubset := make([]shamir.PriShare, absoluteThreshold)
			copy(outputSubset, relevantSubset)
			usedSharesChannel <- outputSubset
			hintedPeopleChannel <- hint
		}
	}
}

func LeavesHintedTOptUsedIndisRecoveryParallelized(f shamir.Field,
	recovered []uint16, relevantSubset []shamir.PriShare,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte) (bool, uint16, error) {
	isEncryptionMatched, hint, _, err := crypto_protocols.GetThresholdedIndisShareMatchBinExt(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
		return isEncryptionMatched, 0, err
	}
	return isEncryptionMatched, hint, nil
}

func UpdateHints(packet HintedTPacket, recovered []uint16,
	hintedTrustees *[]int, secretIndex int) {
	runRelevantEncryptions := packet.RelevantEncryptions[secretIndex]
	runRelevantNonce := packet.Nonce
	isEncryptionMatched, hint, _, err := crypto_protocols.GetThresholdedIndisShareMatchBinExt(
		recovered, runRelevantNonce, runRelevantEncryptions)
	if err != nil {
		log.Fatalln(err)
	}
	if isEncryptionMatched {
		if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, int(hint)) {
			(*hintedTrustees) = append((*hintedTrustees), int(hint))
		}
	}
}
