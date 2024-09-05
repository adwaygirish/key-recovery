package utils

// Generate the tree structure for secret sharing with two layers
// The threshold for the shares layer is fixed at 5
func GenerateTwoLayeredTree(trustees int, percentageThreshold int,
	absoluteThreshold int, percentageSubsecretsThreshold int,
	noOfSubsecrets int) ([]int, []int, []int) {
	subsecretsThreshold := CeilDivide((percentageSubsecretsThreshold *
		noOfSubsecrets), 100)
	noOfLeavesShares := FloorDivide((absoluteThreshold * 100),
		percentageThreshold)
	outputDistribution := []int{noOfSubsecrets}
	var leavesLayerDistribution []int
	for i := 0; i < noOfSubsecrets; i++ {
		leavesLayerDistribution = append(leavesLayerDistribution,
			noOfLeavesShares)
	}
	layerwiseThresholds := []int{subsecretsThreshold, absoluteThreshold}
	return layerwiseThresholds, outputDistribution, leavesLayerDistribution
}

func GenerateAdditiveTwoLayeredTree(trustees int, percentageThreshold int,
	absoluteThreshold int, noOfSubsecrets int) []int {
	noOfLeavesShares := FloorDivide((absoluteThreshold * 100), percentageThreshold)
	var leavesLayerDistribution []int
	for i := 0; i < noOfSubsecrets; i++ {
		leavesLayerDistribution = append(leavesLayerDistribution,
			noOfLeavesShares)
	}
	return leavesLayerDistribution
}

func GenerateAdditiveTwoLayeredTreeSingleShare(trustees, percentageThreshold,
	absoluteThreshold, noOfSubsecrets int) []int {
	noOfLeavesShares := FloorDivide((absoluteThreshold * 100), percentageThreshold)
	var leavesLayerDistribution []int

	// For ensuring that each person receives one share
	// Some of the subsecrets will have less shares than the others
	uniformPacketsNum := noOfSubsecrets * noOfLeavesShares
	extraShares := uniformPacketsNum % trustees
	reductions := make([]int, noOfSubsecrets)
	for i := 0; i < extraShares; i++ {
		reductions[i%noOfSubsecrets] += 1
	}
	for i := 0; i < noOfSubsecrets; i++ {
		requiredLeavesNum := noOfLeavesShares - reductions[i]
		leavesLayerDistribution = append(leavesLayerDistribution,
			requiredLeavesNum)
	}
	return leavesLayerDistribution
}
