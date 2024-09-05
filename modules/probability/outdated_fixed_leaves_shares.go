package probability

import (
	"key_recovery/modules/errors"
	"log"
)

// ***********************PDF***********************
// ***********************Total***********************
// ***********************Additive***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
// The number of shares in the leaves layer is fixed
func GetSimpleProbability(simulations, layers, threshold, trustees,
	anonymity, largestShareSetSize, smallestShareSetSize,
	layerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	// for i := 0; i < trustees; i++ {
	// 	results[i+1] = 0
	// }
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePackets(layers,
		threshold, trustees, anonymity, layerPacketsNum)
	// fmt.Println("******", len(peoplePackets))
	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := threshold * layerPacketsNum / 100
	// fmt.Println("Leaves Threshold", leavesLayerThreshold)

	// The value of the leaves threshold should be less than the limit set
	// if leavesLayerThreshold > largestShareSetSize {
	// 	leavesLayerThreshold = largestShareSetSize
	// }

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for i := 0; i < simulations; i++ {
		// fmt.Println(i, "Threshold", leavesLayerThreshold)
		TotalRecovery(peoplePackets, layerWiseChildren, layers,
			layerPacketsNum, trustees, leavesLayerThreshold,
			results, results_anon)
		// fmt.Println(i)
	}
	return results, results_anon, nil
}

// ***********************PDF***********************
// ***********************Total***********************
// ***********************Thresholded***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
func GetThresholdedProbability(simulations, layers, threshold, upperThreshold,
	trustees, anonymity, largestShareSetSize, smallestShareSetSize,
	layerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	// for i := 0; i < trustees; i++ {
	// 	results[i+1] = 0
	// }
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePackets(layers,
		threshold, trustees, anonymity, layerPacketsNum)
	// fmt.Println("******", len(peoplePackets))
	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := threshold * layerPacketsNum / 100
	upperLayerThreshold := upperThreshold * layerPacketsNum / 100

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for i := 0; i < simulations; i++ {
		// fmt.Println(i, "Threshold", leavesLayerThreshold)
		TotalRecovery(peoplePackets, layerWiseChildren, layers,
			upperLayerThreshold, trustees, leavesLayerThreshold,
			results, results_anon)
		// fmt.Println(i)
	}
	return results, results_anon, nil
}

// ***********************PDF***********************
// ***********************Numwise***********************
// ***********************Additive***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
func GetSimpleProbabilityNumwiseRun(simulations, layers, threshold, trustees,
	anonymity, largestShareSetSize, smallestShareSetSize,
	layerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	// for i := 0; i < trustees; i++ {
	// 	results[i+1] = 0
	// }
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePackets(layers,
		threshold, trustees, anonymity, layerPacketsNum)
	// fmt.Println("******", len(peoplePackets))
	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := threshold * layerPacketsNum / 100
	// fmt.Println("Leaves Threshold", leavesLayerThreshold)

	// The value of the leaves threshold should be less than the limit set
	// if leavesLayerThreshold > largestShareSetSize {
	// 	leavesLayerThreshold = largestShareSetSize
	// }

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize < anonymity; runSize++ {
		// fmt.Println(runSize)
		for i := 0; i < simulations; i++ {
			// fmt.Println(i)
			// fmt.Println(i, "Threshold", leavesLayerThreshold)
			isSuccess := NumwiseRecovery(peoplePackets, layerWiseChildren, layers,
				layerPacketsNum, trustees, leavesLayerThreshold, runSize)
			if isSuccess == 1 {
				results[runSize] += 1
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}

// ***********************CDF***********************
// ***********************Numwise***********************
// ***********************Additive***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
func GetSimpleProbabilityNumwiseRunCDF(simulations, layers, threshold, trustees,
	anonymity, largestShareSetSize, smallestShareSetSize,
	layerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	// for i := 0; i < trustees; i++ {
	// 	results[i+1] = 0
	// }
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePackets(layers,
		threshold, trustees, anonymity, layerPacketsNum)
	// fmt.Println("******", len(peoplePackets))
	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := threshold * layerPacketsNum / 100
	// fmt.Println("Leaves Threshold", leavesLayerThreshold)

	// The value of the leaves threshold should be less than the limit set
	// if leavesLayerThreshold > largestShareSetSize {
	// 	leavesLayerThreshold = largestShareSetSize
	// }

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		// fmt.Println(runSize)
		for i := 0; i < simulations; i++ {
			// fmt.Println(i)
			// fmt.Println(i, "Threshold", leavesLayerThreshold)
			isSuccess := NumwiseRecovery(peoplePackets, layerWiseChildren, layers,
				layerPacketsNum, trustees, leavesLayerThreshold, runSize)
			if isSuccess >= 0 {
				results[runSize] += 1
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}

// ***********************CDF***********************
// ***********************Numwise***********************
// ***********************Thresholded***********************
// Evaluates the probability for the case where the threshold is
// set for the leaves layer as well as the layers above
func GetThresholdedProbabilityNumwiseRunCDF(simulations, layers, threshold,
	upperThreshold, trustees,
	anonymity, largestShareSetSize, smallestShareSetSize,
	layerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	// for i := 0; i < trustees; i++ {
	// 	results[i+1] = 0
	// }
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePackets(layers,
		threshold, trustees, anonymity, layerPacketsNum)
	// fmt.Println("******", len(peoplePackets))
	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := threshold * layerPacketsNum / 100
	upperLayerThreshold := upperThreshold * layerPacketsNum / 100
	// fmt.Println("Leaves Threshold", leavesLayerThreshold)

	// The value of the leaves threshold should be less than the limit set
	// if leavesLayerThreshold > largestShareSetSize {
	// 	leavesLayerThreshold = largestShareSetSize
	// }

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		// fmt.Println(runSize)
		for i := 0; i < simulations; i++ {
			// fmt.Println(i)
			// fmt.Println(i, "Threshold", leavesLayerThreshold)
			isSuccess := NumwiseRecovery(peoplePackets,
				layerWiseChildren, layers,
				upperLayerThreshold, trustees, leavesLayerThreshold, runSize)
			if isSuccess >= 0 {
				results[runSize] += 1
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}
