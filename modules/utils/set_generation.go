package utils

// GenerateSubsets generates all possible subsets of a slice
func GeneratePowerSet(nums []int) [][]int {
	var result [][]int
	var subset []int

	var dfs func(int)
	dfs = func(index int) {
		if index == len(nums) {
			// Add the current subset to the result
			temp := make([]int, len(subset))
			copy(temp, subset)
			result = append(result, temp)
			return
		}

		// Exclude the current element
		dfs(index + 1)

		// Include the current element
		subset = append(subset, nums[index])
		dfs(index + 1)

		// Backtrack
		subset = subset[:len(subset)-1]
	}

	dfs(0)
	return result
}

// Get subset of a certain size
func GenerateSubsetsOfSizeRecursive(set []int, k int) [][]int {
	var subsets [][]int

	// Helper function to generate subsets recursively
	var backtrack func(start int, current []int)
	backtrack = func(start int, current []int) {
		if len(current) == k {
			// Add the subset to the result if its size matches 'k'
			subset := make([]int, k)
			copy(subset, current)
			subsets = append(subsets, subset)
			return
		}

		// Generate subsets recursively
		for i := start; i < len(set); i++ {
			current = append(current, set[i])
			backtrack(i+1, current)
			current = current[:len(current)-1]
		}
	}

	backtrack(0, []int{})
	return subsets
}

func GenerateSubsetsOfSize(set []int, k int) [][]int {
	var subsets [][]int
	n := len(set)

	// Initialize the first combination
	current := make([]int, k)
	for i := 0; i < k; i++ {
		current[i] = i
	}

	for {
		// Generate the current subset based on the indices in `current`
		subset := make([]int, k)
		for i := 0; i < k; i++ {
			subset[i] = set[current[i]]
		}
		subsets = append(subsets, subset)

		// Find the rightmost index that can be incremented
		i := k - 1
		for i >= 0 && current[i] == n-k+i {
			i--
		}

		// If no such index exists, we're done
		if i < 0 {
			break
		}

		// Increment the current index and reset the following indices
		current[i]++
		for j := i + 1; j < k; j++ {
			current[j] = current[j-1] + 1
		}
	}

	return subsets
}

// GenerateIndicesSet gives a set of possible indices in the subset
func GenerateIndicesSet(size int) []int {
	indicesSet := make([]int, size)
	for i := 0; i < size; i++ {
		indicesSet[i] = i
	}
	return indicesSet
}

// GenerateOffsettedIndicesSet gives a set of possible indices in the subset
func GenerateOffsettedIndicesSet(size int, offset int) []int {
	var indicesSet []int
	for i := 0; i < size; i++ {
		indicesSet = append(indicesSet, i+offset)
	}
	return indicesSet
}

// FindDifference returns the elements that are present in slice1 but not in slice2
func FindDifference(slice1, slice2 []int) []int {
	difference := []int{}

	// Create a map to store the elements of slice2 for efficient lookups
	slice2Map := make(map[int]bool)
	for _, element := range slice2 {
		slice2Map[element] = true
	}

	// Iterate over elements of slice1
	for _, element := range slice1 {
		// Check if the element is not present in slice2
		if !slice2Map[element] {
			difference = append(difference, element)
		}
	}

	return difference
}
