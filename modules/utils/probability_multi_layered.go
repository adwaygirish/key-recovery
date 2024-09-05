package utils

import (
	"fmt"
	randm "math/rand"
	"time"
)

// This function returns the number of layers needed for backing up the secret
func GetLevels(trustees int, largestSetSize int) int {
	levels := 2
	for {
		product := 1
		for i := 0; i < levels; i++ {
			product = product * largestSetSize
		}
		if product >= trustees {
			break
		} else {
			levels = levels + 1
		}
	}
	return levels
}

// Get distribution of the subsecrets and secrets
// This distribution is based on the fact that the number of
// subsecrets and shares can be 3, 4, or 5
func GetOutputDistribution(trustees int, noOfLevels int, largestShareSetSize int,
	smallestShareSetSize int) ([]int, int) {
	var distribution []int
	for i := 0; i < noOfLevels; i++ {
		distribution = append(distribution, smallestShareSetSize)
	}
	outputProduct := GetProduct(distribution)
	outputDistribution := make([]int, len(distribution))
	copy(outputDistribution, distribution)
	for {
		// Increment the numbers in the distribution
		for i := len(distribution) - 1; i >= 0; i-- {
			if distribution[i] == largestShareSetSize {
				distribution[i] = smallestShareSetSize
			} else {
				distribution[i] = distribution[i] + 1
				product := GetProduct(distribution)
				// The closer the distribution is to the number of nodes,
				// the better it is to choose it for distributing the secret
				if ((product-trustees) < (outputProduct-trustees) &&
					product >= trustees) || ((outputProduct - trustees) < 0) {
					copy(outputDistribution, distribution)
					outputProduct = product
				}
				break
			}
		}
		// Terminating condition for the infinite loop
		if CheckAllElementsSame(distribution) &&
			distribution[0] == largestShareSetSize {
			break
		}
	}
	fmt.Println(outputDistribution)
	return outputDistribution, outputProduct
}

// This function provides the distribution of the last layer of the tree
func GetLeavesDistribution(outputDistribution []int, trustees int,
	outputProduct int) []int {
	var leavesDistribution []int
	leavesDistNum := GetProduct(outputDistribution[:len(outputDistribution)-1])
	for i := 0; i < leavesDistNum; i++ {
		leavesDistribution = append(leavesDistribution,
			outputDistribution[len(outputDistribution)-1])
	}
	difference := outputProduct - trustees
	jump := outputDistribution[len(outputDistribution)-2]
	startIndex := 0
	index := startIndex
	for {
		if difference > 0 {
			leavesDistribution[index] -= 1
			index = index + jump
			if index >= len(leavesDistribution) {
				startIndex += 1
				index = startIndex
			}
			difference -= 1
		} else {
			break
		}
	}
	return leavesDistribution
}

// This function returns the structure of the tree for secret distribution
// We will have trees where the nodes will have either 3, 4 or 5 children
// This is so that we have less cases of nodes with 2 children
// The function outputs the number of levels needed for secret sharing,
// the number of nodes in each layer other than the leaves, and the distribution
// of the leaves
// This function has different number of leaves for the last layer such that
// the total number of leaves is equal to the number of trustees
func SplitShares(trustees int, largestShareSetSize int,
	smallestShareSetSize int) (int, []int, []int) {
	// Get the number of levels needed for backing the secret
	noOfLevels := GetLevels(trustees, largestShareSetSize)
	// Get the distribution of the nodes in the tree
	outputDistribution, outputProduct := GetOutputDistribution(trustees,
		noOfLevels, largestShareSetSize, smallestShareSetSize)
	leavesDistribution := GetLeavesDistribution(outputDistribution, trustees,
		outputProduct)

	return noOfLevels, outputDistribution[:len(outputDistribution)-1],
		leavesDistribution
}

// This function is similar to SplitShares but with only one difference
// The number of leaves in the last layer is the same for all the subsecrets
func MulSplitShares(trustees int, largestShareSetSize int,
	smallestShareSetSize int) (int, []int, []int, []int) {
	// Get the number of levels needed for backing the secret
	noOfLevels := GetLevels(trustees, largestShareSetSize)
	// Get the distribution of the nodes in the tree
	outputDistribution, outputProduct := GetOutputDistribution(trustees,
		noOfLevels, largestShareSetSize, smallestShareSetSize)
	leavesDistribution := GetLeavesDistribution(outputDistribution, outputProduct,
		outputProduct)
	var layerwiseThresholds []int
	layerwiseThresholds = append(layerwiseThresholds, outputDistribution...)
	layerwiseThresholds = append(layerwiseThresholds, leavesDistribution[0])
	return noOfLevels, outputDistribution[:len(outputDistribution)-1],
		leavesDistribution, layerwiseThresholds
}

// This function randomly assigns the number of shares to each person
// In general, the number of shares is more than the number of trustees
// Therefore, this function assigns the number of shares each person should
// receive
func GetPersonWiseShareNumber(trustees int, totalShares int,
	sharesPerPerson int) ([]int, int) {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	outputShareNumbers := make([]int, trustees)
	for i := range outputShareNumbers {
		outputShareNumbers[i] = sharesPerPerson
	}
	sharesLeft := totalShares - trustees*sharesPerPerson
	var maxSharesPerPerson int
	allTrustees := GenerateIndicesSet(trustees)
	var assignedTrustees []int
	for i := 0; i < sharesLeft; i++ {
		leftTrustees := FindDifference(allTrustees, assignedTrustees)
		// Generate a random index
		randomIndex := rng.Intn(len(leftTrustees))
		assignedTrustee := leftTrustees[randomIndex]
		// Retrieve the random element
		assignedTrustees = append(assignedTrustees, assignedTrustee)
		outputShareNumbers[assignedTrustee] += 1
	}
	maxSharesPerPerson = outputShareNumbers[FindMaxElementIndexInt((outputShareNumbers))]
	return outputShareNumbers, maxSharesPerPerson
}

// Here the number of shares for each secret is fixed
// This is outdated and does not apply to the current design
func GenerateProbTree(layers, layerPacketsNum int) ([]int,
	map[int]map[int][]int, int) {
	offset := 1
	var leavesLayer []int
	layerMembers := []int{0}
	layerWiseChildren := make(map[int]map[int][]int)
	for i := 0; i < layers; i++ {
		var layerList []int
		layerChildren := make(map[int][]int)
		for _, l := range layerMembers {
			tempPacketNums := GenerateOffsettedIndicesSet(layerPacketsNum,
				offset)
			layerChildren[l] = tempPacketNums
			layerList = append(layerList, tempPacketNums...)
			offset = offset + layerPacketsNum
			if i == layers-1 {
				leavesLayer = append(leavesLayer, tempPacketNums...)
			}
		}
		layerWiseChildren[i] = layerChildren
		layerMembers = layerList
	}
	return leavesLayer, layerWiseChildren, offset
}

// This function generates the tree structure for the proposed
// multi-layered secret sharing
// That is, the absolute threshold in the leaves is kept fixed
func GenerateProbTreeFixedTh(layers, higherLayerPacketsNum,
	leavesLayerPacketsNum int) ([]int, map[int]map[int][]int, int) {
	offset := 1
	var leavesLayer []int
	layerMembers := []int{0}
	// This is a map that stores the map of parents and children
	// {layer: {parent: [children]}}
	layerWiseChildren := make(map[int]map[int][]int)
	// Generate the tree before the leaves layer
	for i := 0; i < (layers - 1); i++ {
		// For storing the identifiers for the layer just generated
		// This layer becomes the parent for the next layers
		var layerList []int
		// This is for storing the children just generated during this step
		layerChildren := make(map[int][]int)
		for _, l := range layerMembers {
			// Generate the identifiers for this particular parent
			tempPacketNums := GenerateOffsettedIndicesSet(higherLayerPacketsNum,
				offset)
			layerChildren[l] = tempPacketNums
			// Store the identifiers as the parents for the next iteration
			layerList = append(layerList, tempPacketNums...)
			// Change the offset for generating the identifiers
			offset = offset + higherLayerPacketsNum
		}
		layerWiseChildren[i] = layerChildren
		layerMembers = layerList
	}
	// Generate the leaves layer
	layerChildren := make(map[int][]int)
	for _, l := range layerMembers {
		tempPacketNums := GenerateOffsettedIndicesSet(leavesLayerPacketsNum,
			offset)
		layerChildren[l] = tempPacketNums
		leavesLayer = append(leavesLayer, tempPacketNums...)
		offset = offset + leavesLayerPacketsNum
	}
	layerWiseChildren[layers-1] = layerChildren
	return leavesLayer, layerWiseChildren, offset
}

func GenerateProbTreeFixedThSingleShare(layers, higherLayerPacketsNum,
	leavesLayerPacketsNum, trustees int) ([]int, map[int]map[int][]int, int) {
	offset := 1
	var leavesLayer []int
	layerMembers := []int{0}
	// This is a map that stores the map of parents and children
	// {layer: {parent: [children]}}
	layerWiseChildren := make(map[int]map[int][]int)
	// Generate the tree before the leaves layer
	for i := 0; i < (layers - 1); i++ {
		// For storing the identifiers for the layer just generated
		// This layer becomes the parent for the next layers
		var layerList []int
		// This is for storing the children just generated during this step
		layerChildren := make(map[int][]int)
		for _, l := range layerMembers {
			// Generate the identifiers for this particular parent
			tempPacketNums := GenerateOffsettedIndicesSet(higherLayerPacketsNum,
				offset)
			layerChildren[l] = tempPacketNums
			// Store the identifiers as the parents for the next iteration
			layerList = append(layerList, tempPacketNums...)
			// Change the offset for generating the identifiers
			offset = offset + higherLayerPacketsNum
		}
		layerWiseChildren[i] = layerChildren
		layerMembers = layerList
	}

	// For ensuring that each person receives one share
	// Some of the subsecrets will have less shares than the others
	uniformPacketsNum := higherLayerPacketsNum * leavesLayerPacketsNum
	extraShares := uniformPacketsNum % trustees
	reductions := make([]int, higherLayerPacketsNum)
	for i := 0; i < extraShares; i++ {
		reductions[i%higherLayerPacketsNum] += 1
	}
	// Generate the leaves layer
	layerChildren := make(map[int][]int)
	for ind, l := range layerMembers {
		requiredLeavesNum := leavesLayerPacketsNum - reductions[ind]
		tempPacketNums := GenerateOffsettedIndicesSet(requiredLeavesNum,
			offset)
		layerChildren[l] = tempPacketNums
		leavesLayer = append(leavesLayer, tempPacketNums...)
		offset = offset + requiredLeavesNum
	}
	layerWiseChildren[layers-1] = layerChildren
	return leavesLayer, layerWiseChildren, offset
}

// Generates share packets for each trustee
// This is needed for probability evaluation
func GetSizedRandomPackets(sharePackets []int, trustees int, size int) [][]int {
	var outputPackets [][]int
	tempPackets := make([]int, len(sharePackets))
	copy(tempPackets, sharePackets)
	Shuffle(tempPackets)
	// noOfPackets := len(sharePackets) / trustees
	for i := 0; i < trustees; i++ {
		outputPackets = append(outputPackets, tempPackets[i*size:(i+1)*size])
	}
	// fmt.Println(outputPackets)
	return outputPackets
}
