package utils

import (
	"fmt"
	"testing"
)

func TestFindMaxElementIndex(t *testing.T) {
	testCases := []struct {
		input    []float64
		expected int
	}{
		{[]float64{1.0, 2.0, 3.0, 4.0, 5.0}, 4},
		{[]float64{}, -1},
		{[]float64{11.456, 2.0, 3.998, 4.0, 5.768}, 0},
		{[]float64{11.456, 2.0, 13.998, 4.0, 5.768}, 2},
	}
	// Iterate over test cases
	for _, tc := range testCases {
		// Call the function being tested
		result := FindMaxElementIndex(tc.input)

		// Check if the result matches the expected value
		if result == tc.expected {
			t.Log("Test passed for input: {", tc.input, ", ", tc.expected, "}")
		} else {
			t.Errorf("Test failed: Output of FindMaxElementIndex(%v) = %d; expected %d",
				tc.input, result, tc.expected)
		}
	}
}

func TestGetLargeCombination(t *testing.T) {
	testCases := []struct {
		n int
		r int
	}{
		{5, 2},
		{5, 0},
		{100, 2},
		{50, 5},
		{20, 5},
		{20, 15},
		{100, 99},
		{10, 10},
		{50, 5},
		{100, 5},
		// {100, 20, []int{1}, []int{1}},
	}
	for _, tc := range testCases {
		result := GetLargeCombination(tc.n, tc.r)
		numerator := 1
		denominator := 1
		for _, n := range result[0] {
			numerator *= n
		}
		for _, d := range result[1] {
			denominator *= d
		}
		val := numerator / denominator
		if val == GetCombination(tc.n, tc.r) {
			t.Log("Test passed")
		} else {
			t.Errorf("Test failed: %d, %d, %d, %d", tc.n, tc.r, val,
				GetCombination(tc.n, tc.r))
		}
	}
}

func TestIsInSlice(t *testing.T) {
	testCases := []struct {
		input    []int
		target   int
		expected bool
	}{
		{[]int{1, 2, 3, 4, 5}, 5, true},
		{[]int{1, 2, 3, 4, 5}, 4, true},
		{[]int{5}, 5, true},
		{[]int{1, 2, 3, 4, 5}, 6, false},
		{[]int{}, 1, false},
	}
	// Iterate over test cases
	for _, tc := range testCases {
		// Call the function being tested
		result := IsInSlice(tc.input, tc.target)

		// Check if the result matches the expected value
		if result == tc.expected {
			t.Log("Test passed for input: {", tc.input, ", ", tc.target, "}")
		} else {
			t.Errorf("Test failed: Output of IsInSlice(%d, %d) = %t; expected %t",
				tc.input, tc.target, result, tc.expected)
		}
	}
}

func TestGetIndex(t *testing.T) {
	testCases := []struct {
		input    []int
		target   int
		expected int
	}{
		{[]int{1, 2, 3, 4, 5}, 4, 3},
		{[]int{5}, 5, 0},
		{[]int{1, 2, 3, 4, 5}, 6, -1},
		{[]int{}, 1, -1},
	}
	// Iterate over test cases
	for _, tc := range testCases {
		// Call the function being tested
		result := GetIndex(tc.input, tc.target)

		// Check if the result matches the expected value
		if result == tc.expected {
			t.Log("Test passed for input: {", tc.input, ", ", tc.target, "}")
		} else {
			t.Errorf("Test failed: Output of GetIndex(%d, %d) = %d; expected %d",
				tc.input, tc.target, result, tc.expected)
		}
	}
}

func TestGetLevels(t *testing.T) {
	largestShareSetSize := 5
	testCases := []struct {
		input    int
		expected int
	}{
		{10, 2},
		{25, 2},
		{26, 3},
		{100, 3},
		{150, 4},
	}
	// Iterate over test cases
	for _, tc := range testCases {
		// Call the function being tested
		result := GetLevels(tc.input, largestShareSetSize)

		// Check if the result matches the expected value
		if result == tc.expected {
			t.Log("Test passed for input: {", tc.input, ", ", tc.expected, "}")
		} else {
			t.Errorf("Output of GetLevels(%d) = %d; expected %d", tc.input,
				result, tc.expected)
		}
	}
}

func TestGetOutputDistribution(t *testing.T) {
	testCases := []struct {
		trustees             int
		noOfLevels           int
		largestShareSetSize  int
		smallestShareSetSize int
		expectedDistribution []int
		expectedProduct      int
	}{
		{10, 2, 5, 3, []int{3, 4}, 12},
		{25, 2, 5, 3, []int{5, 5}, 25},
		{21, 2, 5, 3, []int{5, 5}, 25},
		{30, 3, 5, 3, []int{3, 3, 4}, 36},
		{26, 3, 5, 3, []int{3, 3, 3}, 27},
		{100, 3, 5, 3, []int{4, 5, 5}, 100},
		{100, 2, 10, 2, []int{10, 10}, 100},
		{50, 2, 10, 2, []int{5, 10}, 50},
	}
	for _, tc := range testCases {
		dist, prod := GetOutputDistribution(tc.trustees, tc.noOfLevels,
			tc.largestShareSetSize, tc.smallestShareSetSize)
		if prod != tc.expectedProduct {
			t.Error("Mismatch in product for ", tc.trustees, tc.expectedDistribution,
				tc.expectedProduct, prod, dist)
		}
		if len(dist) != len(tc.expectedDistribution) {
			t.Error("Mismatch in no. of elements for ", tc.expectedDistribution,
				dist)
		} else {
			for i, num := range dist {
				if num != tc.expectedDistribution[i] {
					t.Error("Mismatch in distribution for ", tc.expectedDistribution,
						dist)
				}
			}
		}
	}
}

func TestSplitShares(t *testing.T) {
	largestShareSetSize := 5
	smallestShareSetSize := 3
	testCases := []struct {
		input        int
		noOfLevels   int
		distribution []int
		leaves       []int
	}{
		{10, 2, []int{3}, []int{3, 3, 4}},
		{32, 3, []int{3, 3}, []int{3, 3, 4}},
		{36, 3, []int{3, 3}, []int{3, 3, 4}},
		{100, 3, []int{3, 3}, []int{3, 3, 4}},
		{95, 3, []int{3, 3}, []int{3, 3, 4}},
	}
	for _, tc := range testCases {
		// Call the function being tested
		r1, r2, r3 := SplitShares(tc.input, largestShareSetSize,
			smallestShareSetSize)

		// Check if the result matches the expected value
		if r1 == tc.noOfLevels {
			t.Log("Test passed for input: {", tc.input, ", ", tc.noOfLevels, "}")
			t.Log(r2)
			t.Log(r3)
		} else {
			t.Errorf("Output of GetLevels(%d) = %d; expected %d", tc.input,
				r1, tc.noOfLevels)
		}
	}
}

func TestGenerateProbTree(t *testing.T) {
	testCases := []struct {
		layers          int
		layerPacketsNum int
	}{
		{2, 5},
		{2, 10},
	}
	for _, tc := range testCases {
		leavesLayer, layerWiseChildren, offset :=
			GenerateProbTree(tc.layers, tc.layerPacketsNum)
		t.Log(layerWiseChildren)
		t.Log(len(leavesLayer))
		t.Log(offset)
	}
}

func TestGenerateProbTreeFixedTh(t *testing.T) {
	testCases := []struct {
		layers                int
		higherLayerPacketsNum int
		leavesLayerPacketsNum int
		expectedLeaves        int
	}{
		{2, 10, 20, 200},
		{2, 10, 25, 250},
		{2, 20, 20, 400},
		{3, 5, 40, 1000},
	}
	for _, tc := range testCases {
		leavesLayer, layerWiseChildren, _ :=
			GenerateProbTreeFixedTh(tc.layers, tc.higherLayerPacketsNum,
				tc.leavesLayerPacketsNum)
		// Check if the number of leaves are correct
		if len(leavesLayer) != tc.expectedLeaves {
			t.Error("Wrong number of leaves generated for:", tc.layers,
				tc.higherLayerPacketsNum, tc.leavesLayerPacketsNum)
		}
		for i := 0; i < (tc.layers - 1); i++ {
			layerChildren := layerWiseChildren[i]
			for key := range layerChildren {
				if len(layerChildren[key]) != tc.higherLayerPacketsNum {
					t.Error("Wrong number of subsecrets generated for",
						tc.layers, tc.higherLayerPacketsNum, "in the layer", i)
				}
			}
		}
	}
}

func TestGenerateSubsetsOfSize(t *testing.T) {
	testCases := []struct {
		n int
		k int
	}{
		{20, 2},
		{20, 3},
		{150, 4},
		{300, 10},
	}
	for _, tc := range testCases {
		indicesArray := GenerateIndicesSet(tc.n)
		combs := GenerateSubsetsOfSize(indicesArray, tc.k)
		if len(combs) != GetCombination(tc.n, tc.k) {
			t.Error("wrong number of combinations")
		}
	}
}

func TestGenerateSubsetsOfSizeUint16(t *testing.T) {
	testCases := []struct {
		n int
		k int
	}{
		{20, 2},
		{20, 3},
		{150, 4},
		{300, 10},
	}
	for _, tc := range testCases {
		indicesArray := GenerateIndicesSetUint16(tc.n)
		combs := GenerateSubsetsOfSizeUint16(indicesArray, tc.k)
		if len(combs)/int(tc.k) != GetCombination(tc.n, tc.k) {
			t.Error("wrong number of combinations")
		}
	}
}

func TestFlipBitsWithProbability(t *testing.T) {
	testCases := []struct {
		p1 uint16
		p2 uint16
		i1 int
		i2 int
	}{
		{0, 5, 20, 150},
		{50, 50, 20, 150},
	}
	for _, tc := range testCases {
		fmt.Println(tc)
		arr := GenerateTrNonTrBitMatrix(tc.i1, tc.i2)
		_ = FlipBitsWithProbability(arr, tc.p1, tc.p2, tc.i1, tc.i2)
	}
}
