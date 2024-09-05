package probability

import (
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	"log"
	"sync"
)

// ***********************Total***********************
// ***********************Additive***********************
func GetAdditiveProbabilityFixedThTotalCDFParallelized(simulationsDist, simulationsRun,
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

	trusteesNumChannel := make(chan int, simulationsDist*simulationsRun)
	contactsNumChannel := make(chan int, simulationsDist*simulationsRun)

	var wg sync.WaitGroup

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}

		wg.Add(1)

		go TotalRecoveryParallelized(peoplePackets, layerWiseChildren, layers,
			subsecretsNum, trustees, leavesLayerThreshold, simulationsRun,
			trusteesNumChannel, contactsNumChannel, &wg)
	}

	// Wait for the routines to finish
	wg.Wait()

	// Close the channels
	close(trusteesNumChannel)
	close(contactsNumChannel)

	// Update the maps
	for contactsNum := range contactsNumChannel {
		results_anon[contactsNum] += 1
	}
	for trusteesNum := range trusteesNumChannel {
		results[trusteesNum] += 1
	}

	return results, results_anon, nil
}

// ***********************Total***********************
// ***********************Thresholded***********************
func GetThresholdedProbabilityFixedThTotalCDFParallelized(simulationsDist, simulationsRun,
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

	trusteesNumChannel := make(chan int, simulationsDist*simulationsRun)
	contactsNumChannel := make(chan int, simulationsDist*simulationsRun)

	var wg sync.WaitGroup

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}

		wg.Add(1)

		go TotalRecoveryParallelized(peoplePackets, layerWiseChildren, layers,
			upperLayerThreshold, trustees, leavesLayerThreshold, simulationsRun,
			trusteesNumChannel, contactsNumChannel, &wg)
	}

	// Wait for the routines to finish
	wg.Wait()

	// Close the channels
	close(trusteesNumChannel)
	close(contactsNumChannel)

	// Update the maps
	for contactsNum := range contactsNumChannel {
		results_anon[contactsNum] += 1
	}
	for trusteesNum := range trusteesNumChannel {
		results[trusteesNum] += 1
	}
	return results, results_anon, nil
}

// ***********************Total***********************
// ***********************Hinted***********************
func GetHintedTProbabilityFixedThTotalCDFParallelized(simulationsDist, simulationsRun,
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

	trusteesNumChannel := make(chan int, simulationsDist*simulationsRun)
	contactsNumChannel := make(chan int, simulationsDist*simulationsRun)

	var wg sync.WaitGroup

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, sharePersonMap, hintPersonMap, err := CreatePeopleHintedTPacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum, noOfHints)

		if err != nil {
			log.Fatal(err)
		}

		wg.Add(1)

		go TotalHintedTRecoveryParallelized(peoplePackets, layerWiseChildren,
			layers, subsecretsNum, trustees, leavesLayerThreshold,
			sharePersonMap, hintPersonMap, simulationsRun,
			trusteesNumChannel, contactsNumChannel, &wg)
	}

	// Wait for the routines to finish
	wg.Wait()

	// Close the channels
	close(trusteesNumChannel)
	close(contactsNumChannel)

	// Update the maps
	for contactsNum := range contactsNumChannel {
		results_anon[contactsNum] += 1
	}
	for trusteesNum := range trusteesNumChannel {
		results[trusteesNum] += 1
	}

	return results, results_anon, nil
}

// ***********************Total***********************
// ***********************Additive-Expected***********************
func GetExpectedAdditiveProbabilityFixedThTotalCDFParallelized(simulationsDist,
	simulationsRun, layers, threshold, trustees, anonymity, absoluteThreshold,
	subsecretsNum, extraShares int) (map[int]int, map[int]int, error) {
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
	sharesNum := utils.FloorDivide((absoluteThreshold*100), threshold) +
		extraShares

	// Get the number of shares needed for recovering the subsecrets
	// The subsecrets have a fixed threshold
	leavesLayerThreshold := absoluteThreshold

	trusteesNumChannel := make(chan int, simulationsDist*simulationsRun)
	contactsNumChannel := make(chan int, simulationsDist*simulationsRun)

	var wg sync.WaitGroup

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}

		wg.Add(1)

		go TotalRecoveryParallelized(peoplePackets, layerWiseChildren, layers,
			subsecretsNum, trustees, leavesLayerThreshold, simulationsRun,
			trusteesNumChannel, contactsNumChannel, &wg)
	}

	// Wait for the routines to finish
	wg.Wait()

	// Close the channels
	close(trusteesNumChannel)
	close(contactsNumChannel)

	// Update the maps
	for contactsNum := range contactsNumChannel {
		results_anon[contactsNum] += 1
	}
	for trusteesNum := range trusteesNumChannel {
		results[trusteesNum] += 1
	}

	return results, results_anon, nil
}

// ***********************Numwise***********************
// ***********************Additive***********************
// func GetAdditiveProbabilityFixedThNumwiseCDFParallelized(simulations,
// 	layers, threshold, trustees, anonymity, absoluteThreshold,
// 	subsecretsNum int) (map[int]int, map[int]int, error) {
// 	results := make(map[int]int)
// 	results_anon := make(map[int]int)
// 	for i := 0; i < anonymity; i++ {
// 		results[i+1] = 0
// 		results_anon[i+1] = 0
// 	}
// 	// Based on the value of the threshold,
// 	// Obtain the number of packets in the leaves layer
// 	leavesLayerPacketsNum := utils.FloorDivide(absoluteThreshold*100, threshold)
// 	// Obtain the packets to be distributed among people
// 	peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
// 		threshold, trustees, anonymity, subsecretsNum,
// 		leavesLayerPacketsNum)

// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// The percentage threshold should not be greater than 100%
// 	if threshold > 100 {
// 		return nil, nil, errors.ErrInvalidThreshold
// 	}
// 	// Get the number of shares needed for recovering the subsecrets
// 	leavesLayerThreshold := absoluteThreshold

// 	// Since we need a distribution, we need to run the simulation
// 	// multiple times
// 	for runSize := 1; runSize <= anonymity; runSize++ {
// 		NumwiseRecovery(peoplePackets, layerWiseChildren, layers,
// 			subsecretsNum, trustees, leavesLayerThreshold, runSize, simulations,
// 			results, results_anon)
// 	}

// 	return results, results_anon, nil
// }
