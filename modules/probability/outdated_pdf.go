package probability

import (
	"key_recovery/modules/errors"
	"log"
)

// ***********************Total***********************
// ***********************Additive***********************
// Evaluates the probability for the case where the threshold is
// only set for the leaves layer
func GetAdditiveProbabilityFixedTh(simulations, layers, threshold, trustees,
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
		threshold, trustees, anonymity, higherLayerPacketsNum, leavesLayerPacketsNum)

	if err != nil {
		log.Fatal(err)
	}

	// The percentage threshold should not be greater than 100%
	if threshold > 100 {
		return nil, nil, errors.ErrInvalidThreshold
	}
	// Get the number of shares needed for recovering the subsecrets
	// The subsecrets have a fixed threshold
	leavesLayerThreshold := absoluteThreshold

	// Since we need a distribution, we need to run the simulation
	// multiple times
	for i := 0; i < simulations; i++ {
		TotalRecovery(peoplePackets, layerWiseChildren, layers,
			higherLayerPacketsNum, trustees, leavesLayerThreshold,
			results, results_anon)
	}
	return results, results_anon, nil
}
