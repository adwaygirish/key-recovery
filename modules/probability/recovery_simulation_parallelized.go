package probability

import (
	"key_recovery/modules/utils"
	"log"
	"sync"
)

// Here, you run an event until the secret is recovered
func TotalRecoveryParallelized(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold, trustees, leavesLayerThreshold, simulationsRun int,
	trusteesNumChannel chan<- int, contactsNumChannel chan<- int,
	wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < simulationsRun; i++ {
		// fmt.Println(i)
		var obtainedShares, usedShares, obtainedSubsecrets,
			usedSubsecrets, peopleContacted []int
		usedSharesMap := make(map[int][]int)
		noOfPeople := len(peoplePackets)
		accessOrder := utils.GenerateIndicesSet(noOfPeople)
		utils.Shuffle(accessOrder)
		for _, a := range accessOrder {
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
			// If you recover some subsecret (from the penultimate layer),
			// only then run the secret recovery for the layer above
			if isPenRecovered {
				isSecretRecovered, secretsRecovered :=
					CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
						&usedSubsecrets, layerWiseChildren, layers)
				if isSecretRecovered {
					if utils.IsInSlice(secretsRecovered, 0) {
						totalNum := len(peopleContacted)
						contactsNumChannel <- totalNum

						trusteesNum := utils.CountLessThan(peopleContacted, trustees)
						trusteesNumChannel <- trusteesNum
						break
					}
				}
			}
		}
	}
	// fmt.Println("done")
}

// Here, you run an event with hints
func TotalHintedTRecoveryParallelized(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold, trustees, leavesLayerThreshold int,
	sharePersonMap, hintPersonMap map[int]int, simulationsRun int,
	trusteesNumChannel chan<- int, contactsNumChannel chan<- int,
	wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < simulationsRun; i++ {
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
						totalNum := len(peopleContacted)
						contactsNumChannel <- totalNum

						trusteesNum := utils.CountLessThan(peopleContacted, trustees)
						trusteesNumChannel <- trusteesNum
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
}

// Here, you run an event until `runSize` number of trustees have been
// contacted by the user
// func NumwiseRecoveryParallelized(peoplePackets [][]int,
// 	layerWiseChildren map[int]map[int][]int, layers,
// 	upperLayerThreshold,
// 	trustees, leavesLayerThreshold, runSize, simulations int) {
// 	var obtainedShares, usedShares, obtainedSubsecrets,
// 		usedSubsecrets, peopleContacted []int
// 	usedSharesMap := make(map[int][]int)
// 	noOfPeople := len(peoplePackets)
// 	for num := 0; num < 20; num++ {

// 	}
// 	for i := 0; i < simulations; i++ {
// 		accessOrder := utils.GenerateIndicesSet(noOfPeople)
// 		utils.Shuffle(accessOrder)
// 		for _, a := range accessOrder {
// 			// Total set of packets that a user has obtained
// 			obtainedShares = append(obtainedShares, peoplePackets[a]...)
// 			// Slice of people contacted by the user
// 			peopleContacted = append(peopleContacted, a)
// 			relevantData := utils.FindDifference(obtainedShares, usedShares)
// 			// First recover the secret in the leaves layer
// 			isPenRecovered := CheckLeavesRecovery(relevantData,
// 				layerWiseChildren[layers-1], leavesLayerThreshold, &usedShares,
// 				&obtainedSubsecrets, usedSharesMap)
// 			// trusteesNum := utils.CountLessThan(peopleContacted, trustees)
// 			if isPenRecovered {
// 				isSecretRecovered, secretsRecovered :=
// 					CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
// 						&usedSubsecrets, layerWiseChildren, layers)
// 				// Check if any secret has been recovered as well as if
// 				// the main secret has also been recovered
// 				if isSecretRecovered && utils.IsInSlice(secretsRecovered, 0) {
// 					contactsNumChannel <- runSize
// 					break
// 				}
// 			}
// 			if len(peopleContacted) == runSize {
// 				break
// 			}
// 		}
// 	}
// }

func NumwiseRecoveryTrusteesParallelized(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold,
	trustees, leavesLayerThreshold, runSize, simulations int,
	trusteesNumChannel chan<- int, wg *sync.WaitGroup) {
	defer wg.Done()
	var obtainedShares, usedShares, obtainedSubsecrets,
		usedSubsecrets, peopleContacted []int
	usedSharesMap := make(map[int][]int)
	noOfPeople := len(peoplePackets)
	accessOrder := utils.GenerateIndicesSet(noOfPeople)
	utils.Shuffle(accessOrder)
	for i := 0; i < simulations; i++ {
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
					// if len(peopleContacted) == runSize {
					// 	contactsNumChannel <- runSize
					// } else {
					// 	contactsNumChannel <- runSize
					// }
					trusteesNumChannel <- trusteesNum
					break
				}
			}
			if trusteesNum == runSize {
				break
			}
		}
	}
}

// Here, you run an event until the secret is recovered
func TotalCompRecoveryParallelized(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold, trustees, leavesLayerThreshold, simulationsRun int,
	deltaTr, deltaNonTr uint16,
	trusteesNumChannel chan<- int, contactsNumChannel chan<- int,
	wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < simulationsRun; i++ {
		// fmt.Println(i)
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
		for _, a := range accessOrder {
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
			// If you recover some subsecret (from the penultimate layer),
			// only then run the secret recovery for the layer above
			if isPenRecovered {
				isSecretRecovered, secretsRecovered :=
					CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
						&usedSubsecrets, layerWiseChildren, layers)
				if isSecretRecovered {
					if utils.IsInSlice(secretsRecovered, 0) {
						totalNum := len(peopleContacted)
						contactsNumChannel <- totalNum

						trusteesNum := utils.CountLessThan(peopleContacted, trustees)
						trusteesNumChannel <- trusteesNum
						break
					}
				}
			}
		}
	}
	// fmt.Println("done")
}

// Here, you run an event until the secret is recovered
func TotalCompWBAdvObtRecoveryParallelized(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold, trustees, leavesLayerThreshold, simulationsRun int,
	deltaTr, deltaNonTr uint16,
	obtProb, wbProb byte,
	trusteesNumChannel chan<- int, contactsNumChannel chan<- int,
	wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < simulationsRun; i++ {
		// fmt.Println(i)
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
				// If you recover some subsecret (from the penultimate layer),
				// only then run the secret recovery for the layer above
				if isPenRecovered {
					isSecretRecovered, secretsRecovered :=
						CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
							&usedSubsecrets, layerWiseChildren, layers)
					if isSecretRecovered {
						if utils.IsInSlice(secretsRecovered, 0) {
							totalNum := len(peopleContacted)
							contactsNumChannel <- totalNum

							trusteesNum := utils.CountLessThan(peopleContacted, trustees)
							trusteesNumChannel <- trusteesNum
							break
						}
					}
				}
			}
			if probsWB[ind] < wbProb {
				break
			}
		}
	}
}

func TotalWBAdvObtRecoveryParallelized(peoplePackets [][]int,
	layerWiseChildren map[int]map[int][]int, layers,
	upperLayerThreshold, trustees, leavesLayerThreshold, simulationsRun int,
	obtProb, wbProb byte,
	trusteesNumChannel chan<- int, contactsNumChannel chan<- int,
	wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < simulationsRun; i++ {
		// fmt.Println(i)
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
				// If you recover some subsecret (from the penultimate layer),
				// only then run the secret recovery for the layer above
				if isPenRecovered {
					isSecretRecovered, secretsRecovered :=
						CheckAboveLayer(upperLayerThreshold, &obtainedSubsecrets,
							&usedSubsecrets, layerWiseChildren, layers)
					if isSecretRecovered {
						if utils.IsInSlice(secretsRecovered, 0) {
							totalNum := len(peopleContacted)
							contactsNumChannel <- totalNum

							trusteesNum := utils.CountLessThan(peopleContacted, trustees)
							trusteesNumChannel <- trusteesNum
							break
						}
					}
				}
			}
			if probsWB[ind] < wbProb {
				break
			}
		}
	}
}
