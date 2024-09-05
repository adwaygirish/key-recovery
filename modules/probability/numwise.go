package probability

import (
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	"log"
)

// ***********************Numwise***********************
// ***********************Additive***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
// The threshold in the leaves layer is fixed
// This function provides the values for a CDF
func GetAdditiveProbabilityFixedThNumwiseCDF(simulations, layers, threshold,
	trustees, anonymity, absoluteThreshold,
	higherLayerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	leavesLayerPacketsNum := utils.FloorDivide(absoluteThreshold*100, threshold)
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
		threshold, trustees, anonymity, higherLayerPacketsNum,
		leavesLayerPacketsNum)

	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := absoluteThreshold

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		for i := 0; i < simulations; i++ {
			isSuccess := NumwiseRecovery(peoplePackets,
				layerWiseChildren, layers, higherLayerPacketsNum, trustees,
				leavesLayerThreshold, runSize)
			if isSuccess >= 0 {
				results_anon[runSize] += 1
			}
		}
	}
	for runSize := 1; runSize <= trustees; runSize++ {
		for i := 0; i < simulations; i++ {
			isSuccess := NumwiseRecoveryTrustees(peoplePackets,
				layerWiseChildren, layers, higherLayerPacketsNum, trustees,
				leavesLayerThreshold, runSize)
			if isSuccess >= 0 {
				results[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}

func GetAdditiveCompWBAdvObtProbabilityFixedThNumwiseCDF(simulations, layers, threshold,
	trustees, anonymity, absoluteThreshold,
	higherLayerPacketsNum int,
	deltaTr, deltaNonTr uint16,
	obtProb, wbProb byte) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	leavesLayerPacketsNum := utils.FloorDivide(absoluteThreshold*100, threshold)
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
		threshold, trustees, anonymity, higherLayerPacketsNum,
		leavesLayerPacketsNum)

	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := absoluteThreshold

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		for i := 0; i < simulations; i++ {
			isSuccess := NumwiseCompWBAdvObtRecovery(peoplePackets,
				layerWiseChildren, layers, higherLayerPacketsNum, trustees,
				leavesLayerThreshold, runSize, deltaTr, deltaNonTr, obtProb,
				wbProb)
			if isSuccess >= 0 {
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}

func GetAdditiveWBAdvObtProbabilityFixedThNumwiseCDF(simulations, layers, threshold,
	trustees, anonymity, absoluteThreshold,
	higherLayerPacketsNum int,
	obtProb, wbProb byte) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	leavesLayerPacketsNum := utils.FloorDivide(absoluteThreshold*100, threshold)
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
		threshold, trustees, anonymity, higherLayerPacketsNum,
		leavesLayerPacketsNum)

	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := absoluteThreshold

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		for i := 0; i < simulations; i++ {
			isSuccess := NumwiseWBAdvObtRecovery(peoplePackets,
				layerWiseChildren, layers, higherLayerPacketsNum, trustees,
				leavesLayerThreshold, runSize, obtProb, wbProb)
			if isSuccess >= 0 {
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}

// ***********************Numwise***********************
// ***********************Thresholded***********************
// Evaluates the probability for the case where the threshold is
// set for the leaves layer as well as the layers above
func GetThresholdedProbabilityFixedThNumwiseCDF(simulations, layers, threshold,
	upperThreshold, trustees,
	anonymity, absoluteThreshold,
	higherLayerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)

	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}

	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	leavesLayerPacketsNum := (absoluteThreshold * 100) / threshold

	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
		threshold, trustees, anonymity, higherLayerPacketsNum,
		leavesLayerPacketsNum)

	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := absoluteThreshold
	upperLayerThreshold := upperThreshold * higherLayerPacketsNum / 100

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		for i := 0; i < simulations; i++ {
			isSuccess := NumwiseRecovery(peoplePackets,
				layerWiseChildren, layers,
				upperLayerThreshold, trustees, leavesLayerThreshold, runSize)
			if isSuccess >= 0 {
				results[runSize] += 1
				// // totalNum is meant more for the anonymity set
				// // When there is the anonymity set,
				// // the total number of people contacted will be
				// // more than the total number of trustees contacted
				// if totalNum < runSize {
				// 	totalNum = runSize
				// }
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}

// ***********************Numwise***********************
// ***********************Additive***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
func GetAdditiveProbabilityFixedThNumwise(simulations, layers, threshold, trustees,
	anonymity, absoluteThreshold,
	higherLayerPacketsNum int) (map[int]int, map[int]int, error) {
	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < anonymity; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}
	// Based on the value of the threshold,
	// Obtain the number of packets in the leaves layer
	leavesLayerPacketsNum := utils.FloorDivide(absoluteThreshold*100, threshold)
	// Obtain the packets to be distributed among people
	peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
		threshold, trustees, anonymity, higherLayerPacketsNum,
		leavesLayerPacketsNum)

	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	leavesLayerThreshold := absoluteThreshold

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for runSize := 1; runSize <= anonymity; runSize++ {
		for i := 0; i < simulations; i++ {
			isSuccess := NumwiseRecovery(peoplePackets,
				layerWiseChildren, layers, higherLayerPacketsNum, trustees,
				leavesLayerThreshold, runSize)
			if isSuccess > 0 {
				results[runSize] += 1
				results_anon[runSize] += 1
			}
		}
	}
	return results, results_anon, nil
}
