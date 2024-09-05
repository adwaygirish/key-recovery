package secret_binary_extension

import (
	"fmt"
	"log"
	"sync"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
)

func AdditiveOptUsedIndisSecretRecovery(f shamir.Field,
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
		PersonwiseAdditiveOptUsedIndisSecretRecovery(f, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}

func PersonwiseAdditiveOptUsedIndisSecretRecovery(f shamir.Field,
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
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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

	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
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
		runRelevantHashes := peoplePackets[shareDataMap[relevantSubset[0].X]].RelevantHashes
		runRelevantSalt := peoplePackets[shareDataMap[relevantSubset[0].X]].Salt
		isHashMatched, _, err := LeavesAdditiveOptUsedIndisRecovery(f,
			recovered, relevantSubset, runRelevantHashes,
			runRelevantSalt, obtainedSubsecrets, usedShares, -1)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isHashMatched && len((*obtainedSubsecrets)) > 1 {
			SubsecretsAdditiveIndisRecovery(runRelevantHashes,
				runRelevantSalt, *obtainedSubsecrets, secretRecovered,
				recoveredKey)
			if *secretRecovered {
				break
			}
		}
	}
}

func GetRelevantShareData(allShareData []shamir.PriShare,
	usedShares *[][]shamir.PriShare) ([]shamir.PriShare, error) {
	allShareDataCopy := allShareData[:]
	for _, usedShareSet := range *usedShares {
		outputShareSet, err := crypto_protocols.GetSharesSetDifferenceBinExt(allShareDataCopy,
			usedShareSet)
		if err != nil {
			log.Fatalln(err)
			return nil, err
		}
		allShareDataCopy = outputShareSet[:]
	}
	return allShareDataCopy, nil
}

func CheckAlreadyObtainedSubsecrets(f shamir.Field,
	absoluteThreshold int,
	usedShares *[][]shamir.PriShare,
	obtainedSubsecrets *[][]uint16, mostRecentPacket AdditivePacket) {
	mostRecentShareVals := mostRecentPacket.ShareData
	for _, shareVal := range mostRecentShareVals {
		for index, usedShareSet := range *usedShares {
			var relevantShares []shamir.PriShare
			relevantShares = append(relevantShares, shareVal)
			relevantShares = append(relevantShares, usedShareSet[:absoluteThreshold-1]...)
			// Get the recovered secret from the absoluteThreshold number of shares
			recovered, err := f.CombineUniqueX(relevantShares)
			if err != nil {
				fmt.Println(relevantShares)
				log.Fatalln(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			runRelevantHashes := mostRecentPacket.RelevantHashes
			runRelevantSalt := mostRecentPacket.Salt
			isHashMatched, _, err := LeavesAdditiveOptUsedIndisRecovery(f,
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

func LeavesAdditiveOptUsedIndisRecovery(f shamir.Field,
	recovered []uint16, relevantSubset []shamir.PriShare,
	runRelevantHashes [][32]byte, runRelevantSalt [32]byte,
	obtainedSubsecrets *[][]uint16,
	usedShares *[][]shamir.PriShare, index int) (bool, [32]byte, error) {
	isHashMatched, matchedHash, err := crypto_protocols.GetAdditiveIndisShareMatchBinExt(
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
				if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[index], relevantShare) {
					(*usedShares)[index] = append((*usedShares)[index], relevantShare)
				}
			}
		} else {
			emptyShares := make([]shamir.PriShare, 0)
			(*usedShares) = append((*usedShares), emptyShares)
			l := len(*usedShares)
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[l-1], relevantShare) {
					(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
				}
			}
			if !crypto_protocols.CheckSubsecretAlreadyRecoveredBinExt(*obtainedSubsecrets,
				recovered) {
				*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
			}
		}
	}
	return isHashMatched, matchedHash, nil
}

func SubsecretsAdditiveIndisRecovery(
	runRelevantHashes [][32]byte,
	runRelevantSalt [32]byte,
	obtainedSubsecrets [][]uint16, secretRecovered *bool,
	recoveredKey *[]uint16) {
	*secretRecovered, *recoveredKey = crypto_protocols.GetAdditiveSaltedHashMatchBinExt(runRelevantHashes, runRelevantSalt, obtainedSubsecrets)
}

func BasicHashedSecretRecovery(f shamir.Field,
	anonymitySet []shamir.PriShare, accessOrder []int,
	secretKeyHash [32]byte) ([]uint16, error) {
	f.InitializeTables()
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
				relevantSubset := make([]shamir.PriShare, 0, len(relevantIndices))
				for _, ind := range relevantIndices {
					relevantSubset = append(relevantSubset, anonymitySet[ind])
				}
				relevantSubset = append(relevantSubset, anonymitySet[relevantIndex])
				recovered, err := f.CombineUniqueX(relevantSubset)
				if err != nil {
					log.Fatal(err)
				}
				if crypto_protocols.CheckRecSecretKeyBinExt(secretKeyHash,
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
func ThOptUsedIndisSecretRecovery(f shamir.Field,
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
				PersonwiseThOptUsedIndisSecretRecovery(f, peoplePackets,
					absoluteThreshold, &(usedShares[ind1]), &(obtainedSubsecrets[ind1]),
					&(secretRecovered[ind1]), &recoveredSubKey, &trusteesApproached, ind1)

				if secretRecovered[ind1] {
					fmt.Println(recoveredSubKey)
					recoveredKey[ind1] = recoveredSubKey
					fmt.Println(recoveredKey)
				}
			}
			if utils.AllTrue(secretRecovered) {
				break
			}
		}
		if utils.AllTrue(secretRecovered) {
			break
		}
	}

	return recoveredKey
}

// In this case, the idea of recovery is the following:
// Recover only one part of the key and if you are able to recover
// that part, then start going back and try to recover the rest of
// the key
func PersonwiseThOptUsedIndisSecretRecovery(f shamir.Field,
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
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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
		isEncryptionMatched, _, err := LeavesThresholdedOptUsedIndisRecovery(f,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce, obtainedSubsecrets, usedShares, -1)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched {
			// Store the packets of the people whose packets
			// came in handy to recover subsecrets
			// This will be used for other subsecrets
			for _, val := range relevantSubset {
				if !utils.IsInSlice((*trusteesApproached), shareDataMap[val.X]) {
					(*trusteesApproached) = append((*trusteesApproached), shareDataMap[val.X])
				}
			}
			if len((*obtainedSubsecrets)) > 1 {
				SubsecretsThresholdedIndisRecovery(f, runRelevantEncryptions,
					runRelevantNonce, *obtainedSubsecrets, secretRecovered,
					recoveredKey)
				if *secretRecovered {
					break
				}
			}
		}
	}
}

func CheckAlreadyObtainedThresholdedSubsecrets(f shamir.Field,
	absoluteThreshold int, usedShares *[][]shamir.PriShare,
	obtainedSubsecrets *[]shamir.PriShare, mostRecentPacket ThresholdedPacket,
	secretIndex int) bool {
	mostRecentShareVals := mostRecentPacket.ShareData[secretIndex]
	for _, shareVal := range mostRecentShareVals {
		for index, usedShareSet := range *usedShares {
			var relevantShares []shamir.PriShare
			relevantShares = append(relevantShares, shareVal)
			relevantShares = append(relevantShares, usedShareSet[:absoluteThreshold-1]...)
			// Get the recovered secret from the absoluteThreshold number of shares
			recovered, err := f.CombineUniqueX(relevantShares)
			if err != nil {
				fmt.Println(relevantShares)
				log.Fatal(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			runRelevantEncryptions := mostRecentPacket.RelevantEncryptions[secretIndex]
			runRelevantNonce := mostRecentPacket.Nonce
			isHashMatched, _, err := LeavesThresholdedOptUsedIndisRecovery(f,
				recovered, relevantShares, runRelevantEncryptions,
				runRelevantNonce, obtainedSubsecrets, usedShares, index)
			if err != nil {
				log.Fatalln(err)
			}
			if isHashMatched {
				return isHashMatched
			}
		}
	}
	return false
}

func LeavesThresholdedOptUsedIndisRecovery(f shamir.Field,
	recovered []uint16, relevantSubset []shamir.PriShare,
	runRelevantEncryptions [][]byte, runRelevantNonce [32]byte,
	obtainedSubsecrets *[]shamir.PriShare,
	usedShares *[][]shamir.PriShare, index int) (bool, []byte, error) {
	isEncryptionMatched, correctX, matchedEncryption, err := crypto_protocols.GetThresholdedIndisShareMatchBinExt(
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
				if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[index], relevantShare) {
					(*usedShares)[index] = append((*usedShares)[index], relevantShare)
				}
			}
		} else {
			emptyShares := make([]shamir.PriShare, 0)
			(*usedShares) = append((*usedShares), emptyShares)
			l := len(*usedShares)
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[l-1], relevantShare) {
					(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
				}
			}
			recoveredShare := shamir.PriShare{X: correctX, Y: recovered}
			if !crypto_protocols.CheckShareAlreadyUsedBinExt(*obtainedSubsecrets,
				recoveredShare) {
				*obtainedSubsecrets = append(*obtainedSubsecrets, recoveredShare)
			}
		}
	}
	return isEncryptionMatched, matchedEncryption, nil
}

func SubsecretsThresholdedIndisRecovery(
	f shamir.Field,
	runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets []shamir.PriShare, secretRecovered *bool,
	recoveredKey *[]uint16) {
	*secretRecovered, *recoveredKey = crypto_protocols.GetThresholdedNoncedSubsecretMatchBinExt(f, runRelevantEncryptions, runRelevantNonce, obtainedSubsecrets)
}

// This function is meant to work for
// Since the time taken is exponential for the larger thresholds,
// we break the shares into smaller pieces and distribute it among people
// This function does not use any additional information during the
// recovery - that is the user only hashes and the anonymity set
func HintedTOptUsedIndisSecretRecovery(f shamir.Field,
	anonymityPackets []HintedTPacket, accessOrder []int,
	absoluteThreshold int) [][]uint16 {
	anonymitySetSize := len(anonymityPackets)
	var usedShares [][][]shamir.PriShare
	var hintedTrustees []int
	var obtainedSubsecrets [][][]uint16
	var recoveredKey [][]uint16
	var recoveredSubKey []uint16
	var secretRecovered []bool
	var trusteesApproached []int
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
				PersonwiseHintedTOptUsedIndisSecretRecovery(f, peoplePackets,
					absoluteThreshold, &(usedShares[ind1]), &(obtainedSubsecrets[ind1]),
					&(secretRecovered[ind1]), &recoveredSubKey,
					&trusteesApproached, ind1, &hintedTrustees)

				if secretRecovered[ind1] {
					fmt.Println(recoveredSubKey)
					recoveredKey[ind1] = recoveredSubKey
					fmt.Println(recoveredKey)
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

func PersonwiseHintedTOptUsedIndisSecretRecovery(f shamir.Field,
	peoplePackets []HintedTPacket, absoluteThreshold int,
	usedShares *[][]shamir.PriShare, obtainedSubsecrets *[][]uint16,
	secretRecovered *bool, recoveredKey *[]uint16,
	trusteesApproached *[]int, secretIndex int,
	hintedTrustees *[]int) {
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
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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
		isEncryptionMatched, _, err := LeavesHintedTOptUsedIndisRecovery(f,
			recovered, relevantSubset, runRelevantEncryptions,
			runRelevantNonce, obtainedSubsecrets, usedShares, -1, hintedTrustees)
		if err != nil {
			log.Fatalln(err)
			return
		}
		if isEncryptionMatched {
			// Store the packets of the people whose packets
			// came in handy to recover subsecrets
			// This will be used for other subsecrets
			for _, val := range relevantSubset {
				if !utils.IsInSlice((*trusteesApproached), shareDataMap[val.X]) {
					(*trusteesApproached) = append((*trusteesApproached), shareDataMap[val.X])
				}
			}
			if len((*obtainedSubsecrets)) > 1 {
				SubsecretsHintedTIndisRecovery(runRelevantEncryptions,
					runRelevantNonce, *obtainedSubsecrets, secretRecovered,
					recoveredKey)
				if *secretRecovered {
					break
				}
			}
		}
	}
}

func CheckAlreadyObtainedHintedTSubsecrets(f shamir.Field,
	absoluteThreshold int, usedShares *[][]shamir.PriShare,
	obtainedSubsecrets *[][]uint16, mostRecentPacket HintedTPacket,
	secretIndex int, hintedTrustees *[]int) {
	mostRecentShareVals := mostRecentPacket.ShareData[secretIndex]
	for _, shareVal := range mostRecentShareVals {
		for index, usedShareSet := range *usedShares {
			var relevantShares []shamir.PriShare
			relevantShares = append(relevantShares, shareVal)
			relevantShares = append(relevantShares, usedShareSet[:absoluteThreshold-1]...)
			// Get the recovered secret from the absoluteThreshold number of shares
			recovered, err := f.CombineUniqueX(relevantShares)
			if err != nil {
				fmt.Println(relevantShares)
				log.Fatal(err)
			}
			// Considering the hashes and marker info of only one person in
			// the subset is enough
			runRelevantEncryptions := mostRecentPacket.RelevantEncryptions[secretIndex]
			runRelevantNonce := mostRecentPacket.Nonce
			isHashMatched, _, err := LeavesHintedTOptUsedIndisRecovery(f,
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

func LeavesHintedTOptUsedIndisRecovery(f shamir.Field,
	recovered []uint16, relevantSubset []shamir.PriShare,
	runRelevantEncryptions [][]byte, runRelevantNonce [32]byte,
	obtainedSubsecrets *[][]uint16,
	usedShares *[][]shamir.PriShare, index int,
	hintedTrustees *[]int) (bool, []byte, error) {
	// The packet structure is the same as the thresholded model
	// Therefore, we can use the function as is
	isEncryptionMatched, hint, matchedEncryption, err :=
		crypto_protocols.GetThresholdedIndisShareMatchBinExt(
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
				if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[index], relevantShare) {
					(*usedShares)[index] = append((*usedShares)[index], relevantShare)
				}
			}
			if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, int(hint)) {
				(*hintedTrustees) = append((*hintedTrustees), int(hint))
			}
		} else {
			emptyShares := make([]shamir.PriShare, 0)
			(*usedShares) = append((*usedShares), emptyShares)
			l := len(*usedShares)
			for _, relevantShare := range relevantSubset {
				if !crypto_protocols.CheckShareAlreadyUsedBinExt((*usedShares)[l-1], relevantShare) {
					(*usedShares)[l-1] = append((*usedShares)[l-1], relevantShare)
				}
			}
			// recoveredShare := &share.PriShare{I: correctX, V: recovered}
			if !crypto_protocols.CheckSubsecretAlreadyRecoveredBinExt(*obtainedSubsecrets,
				recovered) {
				*obtainedSubsecrets = append(*obtainedSubsecrets, recovered)
			}
			if !crypto_protocols.CheckHintTAlreadyUsed(*hintedTrustees, int(hint)) {
				(*hintedTrustees) = append((*hintedTrustees), int(hint))
			}
		}
	}
	return isEncryptionMatched, matchedEncryption, nil
}

func SubsecretsHintedTIndisRecovery(runRelevantEncryptions [][]byte,
	runRelevantNonce [32]byte,
	obtainedSubsecrets [][]uint16, secretRecovered *bool,
	recoveredKey *[]uint16) {
	*secretRecovered, *recoveredKey = crypto_protocols.GetHintedTNoncedSubsecretMatchBinExt(runRelevantEncryptions, runRelevantNonce, obtainedSubsecrets, recoveryHint)
}

func PersonwiseAdditiveOptUsedIndisSecretRecoveryParallelized(f shamir.Field,
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
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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

	usedSharesChannel := make(chan []shamir.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		go ComputeCombinationsAdditive(f, smallerSubsets[i], relevantShareData,
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

func ComputeCombinationsAdditive(f shamir.Field,
	relevantIndicesSubsets [][]int,
	relevantShareData []shamir.PriShare,
	peoplePackets []AdditivePacket,
	shareDataMap map[uint16]int,
	absoluteThreshold int,
	usedSharesChannel chan<- []shamir.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
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

func BasicHashedSecretRecoveryParallelized(f shamir.Field,
	anonymitySet []shamir.PriShare, accessOrder []int,
	secretKeyHash [32]byte) ([]uint16, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	var recovered []uint16
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
			// noOfRoutines := 1
			// for key, value := range routinesMap {
			// 	if noOfSubsets >= key {
			// 		noOfRoutines = value
			// 		break
			// 	}
			// }
			noOfRoutines := 16

			// fmt.Println(noOfRoutines, len(anonymitySet), obtainedLength)

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

			recoveredChannel := make(chan []uint16, 1000)
			var wg sync.WaitGroup
			// For each subset, run it in a separate subroutine
			for i := 0; i < noOfRoutines; i++ {
				wg.Add(1)
				go ComputeCombinationsBasic(f, smallerSubsets[i], anonymitySet,
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

func BasicHashedSecretRecoveryParallelizedAlternate(f shamir.Field,
	anonymitySet []shamir.PriShare, accessOrder []int,
	secretKeyHash [32]byte, threshold int) ([]uint16, error) {
	// The user obtains the information of the anonymity set one-by-one
	// After obtaining two elements, the user tries to recover the secret
	anonymitySetSize := len(anonymitySet)
	var recovered []uint16
	var isRecovered bool
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		if threshold > obtainedLength {
			continue
		}
		indicesSet := accessOrder[:obtainedLength]
		// The combinations with the share of the most recently contacted
		// person is relevant
		relevantIndex := accessOrder[obtainedLength-1]
		// The user tries different thresholds

		// Generate different combinations of the secret shares
		// Generate combinations without the last obtained share
		relevantIndicesSubsets :=
			utils.GenerateSubsetsOfSize(indicesSet[:obtainedLength-1], threshold-1)

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

		recoveredChannel := make(chan []uint16, 1000)
		var wg sync.WaitGroup
		// For each subset, run it in a separate subroutine
		for i := 0; i < noOfRoutines; i++ {
			wg.Add(1)
			go ComputeCombinationsBasic(f, smallerSubsets[i], anonymitySet,
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

func ComputeCombinationsBasic(f shamir.Field,
	thresholdIndicesSubsets [][]int,
	anonymitySet []shamir.PriShare,
	relevantIndex int,
	secretKeyHash [32]byte,
	recoveredChannel chan<- []uint16,
	wg *sync.WaitGroup) {
	defer wg.Done()
	// Try different combinations for recovery
	for _, relevantIndices := range thresholdIndicesSubsets {
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

func PersonwiseThOptUsedIndisSecretRecoveryParallelized(f shamir.Field,
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
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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

	usedSharesChannel := make(chan []shamir.PriShare, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		copySlice := make([]ThresholdedPacket, len(peoplePackets))
		copy(copySlice, peoplePackets)
		go ComputeCombinationsThresholded(f, smallerSubsets[i], relevantShareData,
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

func ComputeCombinationsThresholded(f shamir.Field,
	relevantIndicesSubsets [][]int,
	relevantShareData []shamir.PriShare,
	peoplePackets []ThresholdedPacket,
	shareDataMap map[uint16]int,
	absoluteThreshold int,
	secretIndex int,
	usedSharesChannel chan<- []shamir.PriShare, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for _, indicesSet := range relevantIndicesSubsets {
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

func PersonwiseHintedTOptUsedIndisSecretRecoveryParallelized(f shamir.Field,
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
	var relevantIndices []int
	for i := 0; i < len(relevantShareData); i++ {
		if shareDataMap[relevantShareData[i].X] == len(peoplePackets)-1 {
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
	usedSharesChannel := make(chan []shamir.PriShare, absoluteThreshold*1000)
	// Channel for the hinted people
	hintedPeopleChannel := make(chan uint16, absoluteThreshold*1000)

	var wg sync.WaitGroup
	// For each subset, run it in a separate subroutine
	for i := 0; i < noOfRoutines; i++ {
		wg.Add(1)
		copySlice := make([]HintedTPacket, len(peoplePackets))
		copy(copySlice, peoplePackets)
		go ComputeCombinationsHintedT(f, smallerSubsets[i], relevantShareData,
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

func ComputeCombinationsHintedTUint16(f shamir.Field,
	relevantIndicesSubsets []uint16,
	relevantShareData []shamir.PriShare,
	peoplePackets []HintedTPacket,
	shareDataMap map[uint16]int,
	absoluteThreshold int,
	secretIndex int,
	usedSharesChannel chan<- []shamir.PriShare,
	hintedPeopleChannel chan<- uint16, wg *sync.WaitGroup) {
	defer wg.Done()
	relevantSubset := make([]shamir.PriShare, absoluteThreshold)
	for i := 0; i < len(relevantIndicesSubsets)/absoluteThreshold; i++ {
		indicesSet := relevantIndicesSubsets[i*absoluteThreshold : (i+1)*absoluteThreshold]
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
