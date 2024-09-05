package utils

// Get subset of a certain size
func GenerateSubsetsOfSizeUint16Recursive(set []uint16, k int) []uint16 {
	var subsets []uint16

	// Helper function to generate subsets recursively
	var backtrack func(start uint16, current []uint16)
	backtrack = func(start uint16, current []uint16) {
		if len(current) == k {
			// Add the subset to the result if its size matches 'k'
			subset := make([]uint16, k)
			copy(subset, current)
			subsets = append(subsets, subset...)
			return
		}

		// Generate subsets recursively
		for i := start; i < uint16(len(set)); i++ {
			current = append(current, set[i])
			backtrack(i+1, current)
			current = current[:len(current)-1]
		}
	}

	backtrack(0, []uint16{})
	return subsets
}

func GenerateSubsetsOfSizeUint16(set []uint16, k int) []uint16 {
	capacity := 100000 * k
	if GetCombination(len(set), k)*k > 0 {
		capacity = GetCombination(len(set), k) * k
	}

	subsets := make([]uint16, 0, capacity)
	n := len(set)

	// Initialize the first combination
	current := make([]int, k)
	for i := 0; i < k; i++ {
		current[i] = i
	}

	for {
		// Generate the current subset based on the indices in `current`
		subset := make([]uint16, k)
		for i := 0; i < k; i++ {
			subset[i] = set[current[i]]
		}
		subsets = append(subsets, subset...)

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

func GenerateSubsetsOfSizeUint16Filtered(set []uint16, k int,
	relevantIndices []uint16) []uint16 {
	capacity := 100000 * k
	if GetCombination(len(set), k)*k > 0 {
		capacity = GetCombination(len(set), k) * k
	}

	subsets := make([]uint16, 0, capacity)
	n := len(set)

	// Initialize the first combination
	current := make([]int, k)
	for i := 0; i < k; i++ {
		current[i] = i
	}

	for {
		// Generate the current subset based on the indices in `current`
		subset := make([]uint16, k)
		for i := 0; i < k; i++ {
			subset[i] = set[current[i]]
		}
		if len(GetIntersectionUint16(subset, relevantIndices)) > 0 {
			subsets = append(subsets, subset...)
		}

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
func GenerateIndicesSetUint16(size int) []uint16 {
	indicesSet := make([]uint16, size)
	for i := 0; i < size; i++ {
		indicesSet[i] = uint16(i)
	}
	return indicesSet
}

// GenerateOffsettedIndicesSet gives a set of possible indices in the subset
func GenerateOffsettedIndicesSetUint16(size int, offset uint16) []uint16 {
	var indicesSet []uint16
	for i := 0; i < size; i++ {
		indicesSet = append(indicesSet, uint16(i)+offset)
	}
	return indicesSet
}
