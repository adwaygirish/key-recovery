package probability

import (
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	"log"
)

type ProbEval struct {
	l    int
	th   int
	tr   int
	a    int
	at   int
	hlpn int
}

// ***********************Total***********************
// ***********************Baseline***********************

func GetBaselineProbabilityCDF(simulations, threshold,
	trustees, anonymity int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}

	thresholdNum := utils.FloorDivide(threshold*trustees, 100)

	for i := 0; i < simulations; i++ {
		accessOrder := utils.GenerateIndicesSet(anonymity)
		utils.Shuffle(accessOrder)

		for j := 2; j <= anonymity; j++ {
			peopleContacted := accessOrder[:j][:]
			trusteesNum := utils.CountLessThan(peopleContacted, trustees)

			if trusteesNum >= thresholdNum {
				results_anon[j] += 1
				results[trusteesNum] += 1
				break
			}
		}
	}
	return results, results_anon, nil
}

func GetCompWBAdvObtBaselineProbabilityCDF(simulations, threshold,
	trustees, anonymity int,
	deltaTr, deltaNonTr uint16,
	obtProb, wbProb byte) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}

	thresholdNum := utils.FloorDivide(threshold*trustees, 100)

	for i := 0; i < simulations; i++ {
		actualBitMatrix := utils.GenerateTrNonTrBitMatrix(trustees, anonymity)
		flippedMatrix := utils.FlipBitsWithProbability(actualBitMatrix, deltaTr,
			deltaNonTr, trustees, anonymity)
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

		obtProbs, err := utils.GenerateProbabilityArray(anonymity)
		if err != nil {
			log.Fatalln(err)
		}
		probsWB, err := utils.GenerateProbabilityArray(anonymity)
		if err != nil {
			log.Fatalln(err)
		}

		collectedData := make([]int, 0, anonymity)
		for j := 0; j < anonymity; j++ {
			if obtProbs[j] < obtProb {
				collectedData = append(collectedData, accessOrder[j])
			} else {
				continue
			}
			trusteesNum := utils.CountLessThan(collectedData, trustees)

			if trusteesNum >= thresholdNum {
				results_anon[j+1] += 1
				results[trusteesNum] += 1
				break
			}
			if probsWB[j] < wbProb {
				break
			}
		}
	}
	return results, results_anon, nil
}

func GetWBAdvObtBaselineProbabilityCDF(simulations, threshold,
	trustees, anonymity int,
	obtProb, wbProb byte) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}

	thresholdNum := utils.FloorDivide(threshold*trustees, 100)

	for i := 0; i < simulations; i++ {
		accessOrder := utils.GenerateIndicesSet(anonymity)
		utils.Shuffle(accessOrder)

		obtProbs, err := utils.GenerateProbabilityArray(anonymity)
		if err != nil {
			log.Fatalln(err)
		}
		probsWB, err := utils.GenerateProbabilityArray(anonymity)
		if err != nil {
			log.Fatalln(err)
		}

		collectedData := make([]int, 0, anonymity)
		for j := 0; j < anonymity; j++ {
			if obtProbs[j] < obtProb {
				collectedData = append(collectedData, accessOrder[j])
			} else {
				continue
			}
			trusteesNum := utils.CountLessThan(collectedData, trustees)

			if trusteesNum >= thresholdNum {
				results_anon[j+1] += 1
				results[trusteesNum] += 1
				break
			}
			if probsWB[j] < wbProb {
				break
			}
		}
	}
	return results, results_anon, nil
}

// ***********************Total***********************
// ***********************Additive***********************
func GetAdditiveProbabilityFixedThTotalCDF(simulationsDist, simulationsRun,
	layers, threshold, trustees, anonymity, absoluteThreshold,
	subsecretsNum int) (map[int]int, map[int]int, error) {
	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	sharesNum := utils.FloorDivide((absoluteThreshold * 100), threshold)

	// Get the number of shares needed for recovering the subsecrets
	// The subsecrets have a fixed threshold
	leavesLayerThreshold := absoluteThreshold

	for k := 0; k < simulationsDist; k++ {
		// fmt.Println("*********** xx Simulation xx ****************", k)
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}
		// Since we need a distribution, we need to run the simulation
		// multiple times
		for i := 0; i < simulationsRun; i++ {
			// fmt.Println("*********** Simulation ****************", i)
			TotalRecovery(peoplePackets, layerWiseChildren, layers,
				subsecretsNum, trustees, leavesLayerThreshold,
				results, results_anon)
		}
	}
	return results, results_anon, nil
}

// ***********************Total***********************
// ***********************Thresholded***********************
func GetThresholdedProbabilityFixedThTotalCDF(simulationsDist, simulationsRun,
	layers, threshold, upperThreshold,
	trustees, anonymity, absoluteThreshold,
	subsecretsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	sharesNum := utils.FloorDivide((absoluteThreshold * 100), threshold)

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	// The subsecrets have a fixed threshold
	leavesLayerThreshold := absoluteThreshold
	upperLayerThreshold := utils.FloorDivide(upperThreshold*subsecretsNum, 100)

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}

		// Since we need a distribution, we need to run the simulation
		// multiple times
		for i := 0; i < simulationsRun; i++ {
			TotalRecovery(peoplePackets, layerWiseChildren, layers,
				upperLayerThreshold, trustees, leavesLayerThreshold,
				results, results_anon)
		}
	}
	return results, results_anon, nil
}

// ***********************Total***********************
// ***********************Hinted***********************
func GetHintedTProbabilityFixedThTotalCDF(simulationsDist, simulationsRun,
	layers, threshold, trustees, anonymity, absoluteThreshold,
	subsecretsNum, noOfHints int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	sharesNum := utils.FloorDivide((absoluteThreshold * 100), threshold)

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	// The subsecrets have a fixed threshold
	leavesLayerThreshold := absoluteThreshold

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, sharePersonMap, hintPersonMap, err := CreatePeopleHintedTPacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum, noOfHints)

		if err != nil {
			log.Fatal(err)
		}

		// Since we need a distribution, we need to run the simulation
		// multiple times
		for i := 0; i < simulationsRun; i++ {
			TotalHintedTRecovery(peoplePackets, layerWiseChildren, layers,
				subsecretsNum, trustees, leavesLayerThreshold,
				sharePersonMap, hintPersonMap,
				results, results_anon)
		}
	}
	return results, results_anon, nil
}
