package probability

import (
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
)

// Creates packets for shares for people
// The number of packets is kept fixed in the leaves layer
// When the percentage is changed, then the absolute threshold of
// the leaves layer is changed
func CreatePeoplePackets(layers, threshold, trustees, anonymity,
	layerPacketsNum int) ([][]int, map[int]map[int][]int, error) {
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	var peoplePackets [][]int
	leavesLayer, layerWiseChildren, offset := utils.GenerateProbTree(layers,
		layerPacketsNum)
	totalShares := len(leavesLayer)
	packetsPerTrustee := totalShares / trustees
	if totalShares%trustees != 0 {
		packetsPerTrustee += 1
	}
	totalTrusteeDataNums := packetsPerTrustee * trustees
	extraRandomTrusteeData := utils.GenerateOffsettedIndicesSet(totalTrusteeDataNums-
		totalShares, offset)
	// fmt.Println("Extra", extraRandomTrusteeData)
	totalTrusteeData := append(leavesLayer, extraRandomTrusteeData...)
	offset += totalTrusteeDataNums - totalShares
	sharePackets := utils.GetSizedRandomPackets(totalTrusteeData, trustees,
		packetsPerTrustee)
	peoplePackets = append(peoplePackets, sharePackets...)
	// fmt.Println("Packets per trustees", packetsPerTrustee)
	if anonymity > trustees {
		additionalPeople := anonymity - trustees
		additionalPackets := additionalPeople * packetsPerTrustee
		anonymityData := utils.GenerateOffsettedIndicesSet(additionalPackets,
			offset)
		anonymityPackets := utils.GetSizedRandomPackets(anonymityData, anonymity-trustees,
			packetsPerTrustee)
		peoplePackets = append(peoplePackets, anonymityPackets...)
	}
	// fmt.Println("Leaves layer", layerWiseChildren, (leavesLayer))
	return peoplePackets, layerWiseChildren, nil
}

// Creates packets for shares for people
// The absolute threshold is kept fixed in the leaves layer
// The percentage change in the threshold changes the number of
// leaves
// This function works for the additive version and the thresholded version
// of the subsecrets
func CreatePeoplePacketsFixedTh(layers, threshold, trustees, anonymity,
	subsecretsNum, sharesNum int) ([][]int,
	map[int]map[int][]int, error) {
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	var peoplePackets [][]int
	// Generate the identifiers distributed among the trustees
	leavesLayer, layerWiseChildren, offset := utils.GenerateProbTreeFixedTh(
		layers, subsecretsNum, sharesNum)
	totalShares := len(leavesLayer)
	// Check the number of shares each trustee receives
	packetsPerTrustee := totalShares / trustees
	// If everyone does not receive the same number of shares,
	// give some random blob to the people so that everyone holds the data of
	// the same size
	if totalShares%trustees != 0 {
		packetsPerTrustee += 1
	}
	// Total no. of shares to be distributed among the trustees
	// so that each one of them receives the same size of data
	totalTrusteeDataNums := packetsPerTrustee * trustees
	extraRandomTrusteeData := utils.GenerateOffsettedIndicesSet(
		totalTrusteeDataNums-totalShares, offset)
	totalTrusteeData := append(leavesLayer, extraRandomTrusteeData...)
	offset += totalTrusteeDataNums - totalShares
	// Create packets of a constant size with random shares
	sharePackets := utils.GetSizedRandomPackets(totalTrusteeData, trustees,
		packetsPerTrustee)
	peoplePackets = append(peoplePackets, sharePackets...)
	// This is for the anonymity set
	if anonymity > trustees {
		additionalPeople := anonymity - trustees
		additionalPackets := additionalPeople * packetsPerTrustee
		anonymityData := utils.GenerateOffsettedIndicesSet(additionalPackets,
			offset)
		anonymityPackets := utils.GetSizedRandomPackets(anonymityData, anonymity-trustees,
			packetsPerTrustee)
		peoplePackets = append(peoplePackets, anonymityPackets...)
	}
	// fmt.Println("Leaves layer", layerWiseChildren, (leavesLayer))
	return peoplePackets, layerWiseChildren, nil
}

// Creates packets for shares for people
// The absolute threshold is kept fixed in the leaves layer
// The percentage change in the threshold changes the number of
// leaves
// This function is for the hinted version of the code
// This is pretty much similar to the other version of the code with the
// only difference in the amount of information that we need
// Specifically, we need the person who holds the corresponding share
// And, for each trustee, we need to store the hint that they hold
func CreatePeopleHintedTPacketsFixedTh(layers, threshold, trustees, anonymity,
	subsecretsNum, sharesNum, noOfHints int) ([][]int,
	map[int]map[int][]int, map[int]int, map[int]int, error) {
	if threshold > 100 {
		return nil, nil, nil, nil, errors.ErrInvalidThreshold
	}
	var peoplePackets [][]int
	sharePersonMap := make(map[int]int)
	hintPersonMap := make(map[int]int)
	// Generate the identifiers distributed among the trustees
	leavesLayer, layerWiseChildren, offset := utils.GenerateProbTreeFixedTh(
		layers, subsecretsNum, sharesNum)
	totalShares := len(leavesLayer)
	// Check the number of shares each trustee receives
	packetsPerTrustee := totalShares / trustees
	// If everyone does not receive the same number of shares,
	// give some random blob to the people so that everyone holds the data of
	// the same size
	if totalShares%trustees != 0 {
		packetsPerTrustee += 1
	}
	// Total no. of shares to be distributed among the trustees
	// so that each one of them receives the same size of data
	totalTrusteeDataNums := packetsPerTrustee * trustees
	extraRandomTrusteeData := utils.GenerateOffsettedIndicesSet(
		totalTrusteeDataNums-totalShares, offset)
	totalTrusteeData := append(leavesLayer, extraRandomTrusteeData...)
	offset += totalTrusteeDataNums - totalShares
	// Create packets of a constant size with random shares
	sharePackets := utils.GetSizedRandomPackets(totalTrusteeData, trustees,
		packetsPerTrustee)
	peoplePackets = append(peoplePackets, sharePackets...)
	// This is for the anonymity set
	if anonymity > trustees {
		additionalPeople := anonymity - trustees
		additionalPackets := additionalPeople * packetsPerTrustee
		anonymityData := utils.GenerateOffsettedIndicesSet(additionalPackets,
			offset)
		anonymityPackets := utils.GetSizedRandomPackets(anonymityData, anonymity-trustees,
			packetsPerTrustee)
		peoplePackets = append(peoplePackets, anonymityPackets...)
	}
	// This is for the map between a share and a person
	// The key is the share and the value is the person
	for index, packet := range peoplePackets {
		for _, data := range packet {
			sharePersonMap[data] = index
		}
	}
	// Create a map between the people and the hints they are holding
	trusteesNums := utils.GenerateIndicesSet(trustees)
	utils.Shuffle(trusteesNums)
	hintedTrustees := trusteesNums[:noOfHints][:]
	for i := 0; i < trustees; i++ {
		if hintedTrustees[i%len(hintedTrustees)] != i {
			hintPersonMap[i] = hintedTrustees[i%len(hintedTrustees)]
		} else {
			hintPersonMap[i] = hintedTrustees[(i+1)%len(hintedTrustees)]
		}
	}
	return peoplePackets, layerWiseChildren, sharePersonMap, hintPersonMap, nil
}
