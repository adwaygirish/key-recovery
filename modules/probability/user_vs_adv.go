package probability

import (
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	"log"
	"sync"
)

func GetCompProbabilityCDFParallelized(simulationsDist, simulationsRun,
	layers, threshold, trustees, anonymity, absoluteThreshold,
	subsecretsNum int,
	deltaTr, deltaNonTr uint16) (map[int]int, map[int]int, error) {
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

		go TotalCompRecoveryParallelized(peoplePackets, layerWiseChildren, layers,
			subsecretsNum, trustees, leavesLayerThreshold, simulationsRun,
			deltaTr, deltaNonTr,
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

func GetCompWBAdvObtProbabilityCDFParallelized(simulationsDist, simulationsRun,
	layers, threshold, trustees, anonymity, absoluteThreshold,
	subsecretsNum int,
	deltaTr, deltaNonTr uint16,
	obtProb, wbProb byte) (map[int]int, map[int]int, error) {
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

	trusteesNumChannel := make(chan int, 10000000)
	contactsNumChannel := make(chan int, 10000000)

	var wg sync.WaitGroup

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}

		wg.Add(1)

		go TotalCompWBAdvObtRecoveryParallelized(peoplePackets, layerWiseChildren, layers,
			subsecretsNum, trustees, leavesLayerThreshold, simulationsRun,
			deltaTr, deltaNonTr,
			obtProb, wbProb,
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

func GetWBAdvObtProbabilityCDFParallelized(simulationsDist, simulationsRun,
	layers, threshold, trustees, anonymity, absoluteThreshold,
	subsecretsNum int,
	obtProb, wbProb byte) (map[int]int, map[int]int, error) {
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

	trusteesNumChannel := make(chan int, 10000000)
	contactsNumChannel := make(chan int, 10000000)

	var wg sync.WaitGroup

	for k := 0; k < simulationsDist; k++ {
		// Obtain the packets to be distributed among people
		peoplePackets, layerWiseChildren, err := CreatePeoplePacketsFixedTh(layers,
			threshold, trustees, anonymity, subsecretsNum, sharesNum)

		if err != nil {
			log.Fatal(err)
		}

		wg.Add(1)

		go TotalWBAdvObtRecoveryParallelized(peoplePackets, layerWiseChildren, layers,
			subsecretsNum, trustees, leavesLayerThreshold, simulationsRun,
			obtProb, wbProb,
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
