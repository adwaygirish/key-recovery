package secret_binary_extension

import (
	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
	"log"
	"sync"
)

// **************************************************************************
// **************************************************************************

// ************Functions for additive***************
// **************************************************************************
func AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f shamir.Field,
	anonymityPackets []AdditivePacket, accessOrder []int,
	absoluteThreshold, obtainedLength int) {
	secretRecovered := false
	var usedShares [][]shamir.PriShare
	var obtainedSubsecrets [][]uint16
	var recoveredKey []uint16

	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set

	obtainedPacketsIndices := accessOrder[:obtainedLength]
	var peoplePackets []AdditivePacket
	for _, obtainedPacketIndex := range obtainedPacketsIndices {
		peoplePackets = append(peoplePackets,
			anonymityPackets[obtainedPacketIndex])
	}
	PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelizedPerPersonUint16(f,
		peoplePackets, absoluteThreshold, &usedShares, &obtainedSubsecrets,
		&secretRecovered, &recoveredKey)
}

func PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelizedPerPersonUint16(f shamir.Field,
	peoplePackets []AdditivePacket, absoluteThreshold int,
	usedShares *[][]shamir.PriShare, obtainedSubsecrets *[][]uint16,
	secretRecovered *bool, recoveredKey *[]uint16) {
	// Put all the share data into a slice
	var allShareData []shamir.PriShare
	// Store which shareData corresponds to which person
	shareDataMap := make(map[uint16]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData...)
		// Store the most recently obtained packet
		// The shares of this packet will be used for checking if
		// they lead to the recovery of one of the already obtained subsecrets
		for _, shareData := range peoplePacket.ShareData {
			shareDataMap[(shareData.X)] = i
		}
	}

	if len(allShareData) < absoluteThreshold {
		return
	}
	var relevantIndices []uint16
	for i := 0; i < len(allShareData); i++ {
		if shareDataMap[allShareData[i].X] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, uint16(i))
		}
	}

	shareIndicesSet := utils.GenerateIndicesSetUint16(len(allShareData))

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
		go ComputeCombinationsAdditiveUint16(f, smallerSubsets[i], allShareData,
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
		}
	}
}

// **************************************************************************
// **************************************************************************

// ************Functions for basic***************
// **************************************************************************

func BasicHashedSecretRecoveryParallelizedPerPersonUint16(f shamir.Field,
	anonymitySet []shamir.PriShare, accessOrder []int,
	secretKeyHash [32]byte, obtainedLength int) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret

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
			go ComputeCombinationsBasicPerPersonUint16(f, smallerSubsets[i], anonymitySet,
				relevantIndex, threshold-1, secretKeyHash, recoveredChannel, &wg)
		}

		wg.Wait()

		close(recoveredChannel)
	}
}

func ComputeCombinationsBasicPerPersonUint16(f shamir.Field,
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
		}
	}
}

// **************************************************************************
// **************************************************************************

// ************Functions for thresholded***************
// **************************************************************************
func ThOptUsedIndisSecretRecoveryParallelizedPerPerson(f shamir.Field,
	anonymityPackets []ThresholdedPacket, accessOrder []int,
	absoluteThreshold, obtainedLength int) {
	var usedShares [][][]shamir.PriShare
	var obtainedSubsecrets [][]shamir.PriShare
	emptySubKey := make([]uint16, len(anonymityPackets[0].ShareData[0][0].Y))
	recoveredKey := make([][]uint16, len(anonymityPackets[0].ShareData))
	for i := 0; i < len(anonymityPackets[0].ShareData); i++ {
		copy(recoveredKey[i], emptySubKey)
	}
	var secretRecovered []bool
	var recoveredSubKey []uint16
	for i := 0; i < len(anonymityPackets[0].ShareData); i++ {
		usedShares = append(usedShares, [][]shamir.PriShare{})
		obtainedSubsecrets = append(obtainedSubsecrets, []shamir.PriShare{})
		secretRecovered = append(secretRecovered, false)
	}
	// The user will go to more people until she has obtained her secret
	// The user tries to recover as soon as she has obtained information from
	// two people in the anonymity set
	// First of all, recover the first part of the secret
	f.InitializeTables()
	obtainedPacketsIndices := accessOrder[:obtainedLength]
	var peoplePackets []ThresholdedPacket
	for _, obtainedPacketIndex := range obtainedPacketsIndices {
		peoplePackets = append(peoplePackets,
			anonymityPackets[obtainedPacketIndex])
	}
	for ind1 := 0; ind1 < len(anonymityPackets[0].ShareData); ind1++ {
		if !secretRecovered[ind1] {
			PersonwiseThOptUsedIndisSecretRecoveryParallelizedPerPersonUint16(f, peoplePackets,
				absoluteThreshold, &(usedShares[ind1]), &(obtainedSubsecrets[ind1]),
				&(secretRecovered[ind1]), &recoveredSubKey, ind1)

			if secretRecovered[ind1] {
				recoveredKey[ind1] = recoveredSubKey
			}
		}
	}

}

func PersonwiseThOptUsedIndisSecretRecoveryParallelizedPerPersonUint16(f shamir.Field,
	peoplePackets []ThresholdedPacket, absoluteThreshold int,
	usedShares *[][]shamir.PriShare, obtainedSubsecrets *[]shamir.PriShare,
	secretRecovered *bool, recoveredKey *[]uint16,
	secretIndex int) {
	// Put all the share data into a slice
	var allShareData []shamir.PriShare
	// Store which shareData corresponds to which person
	shareDataMap := make(map[uint16]int)
	for i, peoplePacket := range peoplePackets {
		allShareData = append(allShareData,
			peoplePacket.ShareData[secretIndex]...)
		for _, shareData := range peoplePacket.ShareData[secretIndex] {
			shareDataMap[(shareData.X)] = i
		}
	}
	if len(allShareData) < absoluteThreshold {
		return
	}
	var relevantIndices []uint16
	for i := 0; i < len(allShareData); i++ {
		if shareDataMap[allShareData[i].X] == len(peoplePackets)-1 {
			relevantIndices = append(relevantIndices, uint16(i))
		}
	}
	shareIndicesSet := utils.GenerateIndicesSetUint16(len(allShareData))

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
		go ComputeCombinationsThresholdedUint16(f, smallerSubsets[i], allShareData,
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
		}
	}
}
