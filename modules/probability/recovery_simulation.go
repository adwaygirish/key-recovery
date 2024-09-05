package probability

import (
	"fmt"
	"key_recovery/modules/utils"
	"log"
)

// Here, you run an event until the secret is recovered
func TotalRecovery(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers int,
	upperLayerThreshold int, trustees int, leavesLayerThreshold int,
	results map[int]int, results_anon map[int]int) {
	var obtainedShares, usedShares, obtainedSubsecrets,
		usedSubsecrets, peopleContacted []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	accessOrder := utils.GenerateIndicesSet(noOfPeople)
	utils.Shuffle(accessOrder)
	// fmt.Println(layerWiseChildren)
	// fmt.Println(peoplePackets)
	// fmt.Println(accessOrder)
	for _, a := range accessOrder {
		// fmt.Println("contacted", a)
		obtainedShares = append(obtainedShares, peoplePackets[a]...)
		peopleContacted = append(peopleContacted, a)
		// Shares obtained from the most recently contacted person
		newShares := peoplePackets[a]
		// Check with the already reconstructed subsecrets
		CheckAlreadyUsedShares(usedSharesMap, newShares,
			layerWiseChildren[layers-1], &usedShares)
		relevantData := utils.FindDifference(obtainedShares, usedShares)
		// First recover the secret in the leaves layer
		isPenRecovered := CheckLeavesRecovery(relevantData,
			layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
			&obtainedSubsecrets, usedSharesMap)
		// fmt.Println("recovery update subsecrets", obtainedSubsecrets)
		// fmt.Println("used shares update", usedShares)
		// fmt.Println("obtained shares update", obtainedShares)
		// fmt.Println("used shares map", usedSharesMap)
		// If you recover some subsecret (from the penultimate layer),
		// only then run the secret recovery for the layer above
		if isPenRecovered {
			isSecretRecovered, secretsRecovered :=
				CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
					&usedSubsecrets, layerWiseChildren, layers)
			if isSecretRecovered {
				if utils.IsInSlice(secretsRecovered, 0) {
					// If the secret key has been recovered,
					// then break the loop
					totalNum := len(peopleContacted)
					results_anon[totalNum] += 1
					// This gives the number of trustees
					// This gives the number of elements which have the value
					// less than the variable trustees
					trusteesNum := utils.CountLessThan(peopleContacted, trustees)
					results[trusteesNum] += 1
					break
				}
			}
		}
	}
}

// Here, you run an event with hints
func TotalHintedTRecovery(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold, trustees, leavesLayerThreshold int,
	sharePersonMap, hintPersonMap map[int]int,
	results map[int]int, results_anon map[int]int) {
	var obtainedShares, usedShares, obtainedSubsecrets, usedSubsecrets,
		peopleContacted, hintedPeople []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	accessOrder := utils.GenerateIndicesSet(noOfPeople)
	utils.Shuffle(accessOrder)
	for index, a := range accessOrder {
		obtainedLength := index + 1
		obtainedShares = append(obtainedShares, peoplePackets[a]...)
		peopleContacted = append(peopleContacted, a)
		// Shares obtained from the most recently contacted person
		newShares := peoplePackets[a]
		// Check with the already reconstructed subsecrets
		CheckAlreadyUsedHintedShares(usedSharesMap, newShares,
			layerWiseChildren[layers-1], &usedShares, a, hintPersonMap,
			&hintedPeople)
		relevantData := utils.FindDifference(obtainedShares, usedShares)
		isPenRecovered := CheckHintedLeavesRecovery(relevantData,
			layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
			&obtainedSubsecrets, sharePersonMap, hintPersonMap, &hintedPeople)
		// If you recover some subsecret (from the penultimate layer),
		// only then run the secret recovery for the layer above
		if isPenRecovered {
			isSecretRecovered, secretsRecovered :=
				CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
					&usedSubsecrets, layerWiseChildren, layers)
			if isSecretRecovered {
				if utils.IsInSlice(secretsRecovered, 0) {
					// If the secret key has been recovered,
					// then break the loop
					totalNum := len(peopleContacted)
					results_anon[totalNum] += 1
					// This gives the number of trustees
					// This gives the number of elements which have the value
					// less than the variable trustees
					trusteesNum := utils.CountLessThan(peopleContacted, trustees)
					results[trusteesNum] += 1
					break
				}
			}
		}
		// Based on the hind obtained,
		// change the access order
		if len(hintedPeople) != 0 {
			utils.UpdateOrder(hintedPeople, &accessOrder, obtainedLength)
		}
		// fmt.Println(len(hintedPeople), len(obtainedSubsecrets), obtainedLength)
	}
}

// Here, you run an event until `runSize` number of trustees have been
// contacted by the user
func NumwiseRecovery(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers int, upperLayerThreshold int,
	trustees int, leavesLayerThreshold int, runSize int) int {
	var obtainedShares, usedShares, obtainedSubsecrets,
		usedSubsecrets, peopleContacted []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	accessOrder := utils.GenerateIndicesSet(noOfPeople)
	utils.Shuffle(accessOrder)
	for _, a := range accessOrder {
		// Total set of packets that a user has obtained
		obtainedShares = append(obtainedShares, peoplePackets[a]...)
		// Slice of people contacted by the user
		peopleContacted = append(peopleContacted, a)
		relevantData := utils.FindDifference(obtainedShares, usedShares)
		// First recover the secret in the leaves layer
		isPenRecovered := CheckLeavesRecovery(relevantData,
			layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
			&obtainedSubsecrets, usedSharesMap)
		// trusteesNum := utils.CountLessThan(peopleContacted, trustees)
		if isPenRecovered {
			isSecretRecovered, secretsRecovered :=
				CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
					&usedSubsecrets, layerWiseChildren, layers)
			// Check if any secret has been recovered as well as if
			// the main secret has also been recovered
			if isSecretRecovered && utils.IsInSlice(secretsRecovered, 0) {
				// fmt.Println("recovered here", runSize)
				// if runSize == 3 {
				// 	fmt.Println(obtainedShares)
				// }
				// Check the no. of trustees that have been contacted
				// If the number is exactly the same as the runSize
				// , then send 1; else send 0
				// These numbers will be used for making CDFs and PDFs
				if len(peopleContacted) == runSize {
					return 1
				} else {
					return 0
				}
			}
		}
		if len(peopleContacted) == runSize {
			break
		}
	}
	return -1
}

func NumwiseCompWBAdvObtRecovery(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers, upperLayerThreshold,
	trustees, leavesLayerThreshold, runSize int,
	deltaTr, deltaNonTr uint16, obtProb, wbProb byte) int {
	var obtainedShares, usedShares, obtainedSubsecrets,
		usedSubsecrets, peopleContacted []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	actualBitMatrix := utils.GenerateTrNonTrBitMatrix(trustees, noOfPeople)
	flippedMatrix := utils.FlipBitsWithProbability(actualBitMatrix, deltaTr,
		deltaNonTr, trustees, noOfPeople)
	var firstApproach []int
	var lastApproach []int
	for ind, f := range flippedMatrix {
		if f == 1 {
			firstApproach = append(firstApproach, ind)
		} else {
			lastApproach = append(lastApproach, ind)
		}
	}
	utils.Shuffle(firstApproach)
	utils.Shuffle(lastApproach)
	var accessOrder []int
	accessOrder = append(accessOrder, firstApproach...)
	accessOrder = append(accessOrder, lastApproach...)

	obtProbs, err := utils.GenerateProbabilityArray(noOfPeople)
	if err != nil {
		log.Fatalln(err)
	}
	probsWB, err := utils.GenerateProbabilityArray(noOfPeople)
	if err != nil {
		log.Fatalln(err)
	}
	for ind, a := range accessOrder {
		if obtProbs[ind] < obtProb {
			// Total set of packets that a user has obtained
			obtainedShares = append(obtainedShares, peoplePackets[a]...)
			// Slice of people contacted by the user
			peopleContacted = append(peopleContacted, a)
			relevantData := utils.FindDifference(obtainedShares, usedShares)
			// First recover the secret in the leaves layer
			isPenRecovered := CheckLeavesRecovery(relevantData,
				layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
				&obtainedSubsecrets, usedSharesMap)
			// trusteesNum := utils.CountLessThan(peopleContacted, trustees)
			if isPenRecovered {
				isSecretRecovered, secretsRecovered :=
					CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
						&usedSubsecrets, layerWiseChildren, layers)
				// Check if any secret has been recovered as well as if
				// the main secret has also been recovered
				if isSecretRecovered && utils.IsInSlice(secretsRecovered, 0) {
					// Check the no. of trustees that have been contacted
					// If the number is exactly the same as the runSize
					// , then send 1; else send 0
					// These numbers will be used for making CDFs and PDFs
					if len(peopleContacted) == runSize {
						return 1
					} else {
						return 0
					}
				}
			}
		}
		if len(peopleContacted) == runSize || probsWB[ind] < wbProb {
			break
		}
	}
	return -1
}

func NumwiseWBAdvObtRecovery(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers, upperLayerThreshold,
	trustees, leavesLayerThreshold, runSize int,
	obtProb, wbProb byte) int {
	var obtainedShares, usedShares, obtainedSubsecrets,
		usedSubsecrets, peopleContacted []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	accessOrder := utils.GenerateIndicesSet(noOfPeople)
	utils.Shuffle(accessOrder)

	obtProbs, err := utils.GenerateProbabilityArray(noOfPeople)
	if err != nil {
		log.Fatalln(err)
	}
	probsWB, err := utils.GenerateProbabilityArray(noOfPeople)
	if err != nil {
		log.Fatalln(err)
	}
	for ind, a := range accessOrder {
		if obtProbs[ind] < obtProb {
			// Total set of packets that a user has obtained
			obtainedShares = append(obtainedShares, peoplePackets[a]...)
			// Slice of people contacted by the user
			peopleContacted = append(peopleContacted, a)
			relevantData := utils.FindDifference(obtainedShares, usedShares)
			// First recover the secret in the leaves layer
			isPenRecovered := CheckLeavesRecovery(relevantData,
				layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
				&obtainedSubsecrets, usedSharesMap)
			// trusteesNum := utils.CountLessThan(peopleContacted, trustees)
			if isPenRecovered {
				isSecretRecovered, secretsRecovered :=
					CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
						&usedSubsecrets, layerWiseChildren, layers)
				// Check if any secret has been recovered as well as if
				// the main secret has also been recovered
				if isSecretRecovered && utils.IsInSlice(secretsRecovered, 0) {
					// Check the no. of trustees that have been contacted
					// If the number is exactly the same as the runSize
					// , then send 1; else send 0
					// These numbers will be used for making CDFs and PDFs
					if len(peopleContacted) == runSize {
						return 1
					} else {
						return 0
					}
				}
			}
		}
		if len(peopleContacted) == runSize || probsWB[ind] < wbProb {
			// fmt.Println(len(peopleContacted), runSize, probsWB[ind])
			break
		}
	}
	return -1
}

func NumwiseRecoveryTrustees(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers int, upperLayerThreshold int,
	trustees int, leavesLayerThreshold int, runSize int) int {
	var obtainedShares, usedShares, obtainedSubsecrets,
		usedSubsecrets, peopleContacted []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	accessOrder := utils.GenerateIndicesSet(noOfPeople)
	utils.Shuffle(accessOrder)
	for _, a := range accessOrder {
		// Total set of packets that a user has obtained
		obtainedShares = append(obtainedShares, peoplePackets[a]...)
		// Slice of people contacted by the user
		peopleContacted = append(peopleContacted, a)
		relevantData := utils.FindDifference(obtainedShares, usedShares)
		// First recover the secret in the leaves layer
		isPenRecovered := CheckLeavesRecovery(relevantData,
			layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
			&obtainedSubsecrets, usedSharesMap)
		trusteesNum := utils.CountLessThan(peopleContacted, trustees)
		if isPenRecovered {
			isSecretRecovered, secretsRecovered :=
				CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
					&usedSubsecrets, layerWiseChildren, layers)
			// Check if any secret has been recovered as well as if
			// the main secret has also been recovered
			if isSecretRecovered && utils.IsInSlice(secretsRecovered, 0) {
				// Check the no. of trustees that have been contacted
				// If the number is exactly the same as the runSize
				// , then send 1; else send 0
				// These numbers will be used for making CDFs and PDFs
				if (trusteesNum) == runSize {
					return 1
				} else {
					return 0
				}
			}
		}
		if (trusteesNum) == runSize {
			break
		}
	}
	return -1
}

func CheckAlreadyUsedShares(usedSharesMap map[int][]int, newShares []int,
	leavesChildren map[int][]int, usedShares *[]int) {
	for key, value := range usedSharesMap {
		var allShares []int
		allShares = append(allShares, value...)
		allShares = append(allShares, newShares...)
		intersection := utils.GetIntersection(allShares, leavesChildren[key])
		// fmt.Println("intersection", intersection)
		intersectionNew := utils.GetIntersection(intersection, newShares)
		if len(intersectionNew) > 0 {
			usedSharesMap[key] = append(usedSharesMap[key], intersectionNew...)
			(*usedShares) = append((*usedShares), intersectionNew...)
		}
	}
}

func CheckAlreadyUsedHintedShares(usedSharesMap map[int][]int, newShares []int,
	leavesChildren map[int][]int, usedShares *[]int, a int,
	hintPersonMap map[int]int, hintedPeople *[]int) {
	for key, value := range usedSharesMap {
		var allShares []int
		allShares = append(allShares, value...)
		allShares = append(allShares, newShares...)
		intersection := utils.GetIntersection(allShares, leavesChildren[key])
		intersectionNew := utils.GetIntersection(intersection, newShares)
		if len(intersectionNew) > 0 {
			// Since these are shares from a new person contacted,
			// we do not need to check if this share is already present
			usedSharesMap[key] = append(usedSharesMap[key], intersectionNew...)
			(*usedShares) = append((*usedShares), intersectionNew...)
			// Now, check for the new hints obtained from the person
			newHint := hintPersonMap[a]
			if !utils.IsInSlice((*hintedPeople), newHint) {
				(*hintedPeople) = append((*hintedPeople), newHint)
			}
		}
	}
}

// Checks if some secret has been recovered in the leaves layer
func CheckLeavesRecovery(relevantData []int, leavesChildren map[int][]int,
	leavesLayerThreshold int, usedShares *[]int,
	obtainedSubsecrets *[]int, usedSharesMap map[int][]int) bool {
	isLeavesRecovered := false
	for key, value := range leavesChildren {
		intersection := utils.GetIntersection(relevantData, value)
		// Check if the intersection is greater than the threshold
		if len(intersection) >= leavesLayerThreshold {
			// || utils.IsInSlice(*usedShares, key) {
			// fmt.Println(utils.IsInSlice(*usedShares, key))
			if utils.IsInSlice(*usedShares, key) {
				fmt.Println("Hello", key)
			}
			(*usedShares) = append((*usedShares), intersection...)
			// If the higher layer secret hasn't been recovered, then
			// add it as one of the obtained packets
			if !utils.IsInSlice(*obtainedSubsecrets, key) {
				isLeavesRecovered = true
				(*obtainedSubsecrets) = append((*obtainedSubsecrets), key)
				usedSharesMap[key] = intersection
				// fmt.Println("here leaves", key)
			}
		}
	}
	return isLeavesRecovered
}

// Checks if some secret has been recovered in the leaves layer
func CheckHintedLeavesRecovery(relevantData []int, leavesChildren map[int][]int,
	leavesLayerThreshold int, usedShares *[]int,
	obtainedSubsecrets *[]int, sharePersonMap, hintPersonMap map[int]int,
	hintedPeople *[]int) bool {
	isLeavesRecovered := false
	for key, value := range leavesChildren {
		intersection := utils.GetIntersection(relevantData, value)
		// Check if the intersection is greater than the threshold
		if len(intersection) >= leavesLayerThreshold {
			// || utils.IsInSlice(*usedShares, key) {
			// fmt.Println(utils.IsInSlice(*usedShares, key))
			if utils.IsInSlice(*usedShares, key) {
				fmt.Println("Hello", key)
			}
			// Put the shares that were used for reconstructing the subsecret
			// as one of the
			(*usedShares) = append((*usedShares), intersection...)
			// Check for each share obtained
			// See from which person you obtained the share
			// The packet of that person will reveal a hint
			for _, intersectionVal := range intersection {
				person := sharePersonMap[intersectionVal]
				obtainedHint := hintPersonMap[person]
				if !utils.IsInSlice((*hintedPeople), obtainedHint) {
					(*hintedPeople) = append((*hintedPeople), obtainedHint)
				}
			}
			// If the higher layer secret hasn't been recovered, then
			// add it as one of the obtained subsecrets
			if !utils.IsInSlice(*obtainedSubsecrets, key) {
				isLeavesRecovered = true
				(*obtainedSubsecrets) = append((*obtainedSubsecrets), key)
				// fmt.Println("here leaves", key)
			}
		}
	}
	return isLeavesRecovered
}

// Checks if some secret has been recovered in the layer above
func CheckAboveLayer(layerThreshold int, obtainedSubsecrets *[]int,
	usedSubsecrets *[]int, layerWiseChildren map[int]map[int][]int,
	layers int) (bool, []int) {
	relevantHigherSet := utils.FindDifference(*obtainedSubsecrets,
		*usedSubsecrets)
	isSecretRecovered := false
	var secretsRecovered []int
	if len(relevantHigherSet) >= layerThreshold {
		for childLevel, children := range layerWiseChildren {
			if childLevel == (layers - 1) {
				continue
			}
			// fmt.Println("Hello", childLevel)
			for key, value := range children {
				intersection := utils.GetIntersection(relevantHigherSet, value)
				if len(intersection) >= layerThreshold {
					isSecretRecovered = true
					if !utils.IsInSlice(*obtainedSubsecrets, key) {
						isSecretRecovered = true
						secretsRecovered = append(secretsRecovered, childLevel)
						(*obtainedSubsecrets) =
							append((*obtainedSubsecrets), key)
						(*usedSubsecrets) =
							append((*usedSubsecrets), intersection...)
						// fmt.Println("here above", key)
					}
				}
			}
		}
	}
	return isSecretRecovered, secretsRecovered
}
