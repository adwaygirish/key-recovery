package utils

import (
	"fmt"
	"testing"
)

func TestGenerateTwoLayeredTree(t *testing.T) {
	absoluteThreshold := 5
	trustees := 20
	testCases := []struct {
		percentageThreshold             int
		percentageSubsecretsThreshold   int
		noOfSubsecrets                  int
		expectedDistribution            int
		expectedLeavesLayerDistribution int
	}{
		{50, 100, 10, 10, 10},
		{25, 100, 10, 10, 20},
		{60, 100, 10, 10, 8},
	}
	for _, tc := range testCases {
		layerwiseThresholds, outputDistribution, leavesLayerDistribution :=
			GenerateTwoLayeredTree(trustees, tc.percentageThreshold,
				absoluteThreshold, tc.percentageSubsecretsThreshold, tc.noOfSubsecrets)
		if len(layerwiseThresholds) != 2 {
			t.Error("Wrong layer wise secret generated")
			continue
		}
		if layerwiseThresholds[0] != ((tc.percentageSubsecretsThreshold *
			tc.noOfSubsecrets) / 100) {
			t.Error("Wrong number of subsecrets")
			continue
		}
		if layerwiseThresholds[1] != absoluteThreshold {
			t.Error("Wrong number of shares")
			continue
		}
		if len(outputDistribution) != 1 {
			t.Error("Wrong output distribution generation")
			continue
		}
		if outputDistribution[0] != tc.expectedDistribution {
			t.Error("Wrong value of the distribution", outputDistribution[0])
			continue
		}
		if len(leavesLayerDistribution) != tc.noOfSubsecrets {
			t.Error("Wrong number of total leaves", len(leavesLayerDistribution))
			continue
		}
		for _, l := range leavesLayerDistribution {
			if l != tc.expectedLeavesLayerDistribution {
				t.Error("Wrong number of leaves generated", l)
				break
			}
		}
	}
}

func TestGenerateAdditiveTwoLayeredTreeSingleShare(t *testing.T) {
	absoluteThreshold := 4
	trustees := 20
	testCases := []struct {
		percentageThreshold int
		noOfSubsecrets      int
	}{
		{30, 2},
		{50, 3},
		{60, 4},
		{80, 4},
		{100, 5},
		// {25, 100, 10, 10, 20},
		// {60, 100, 10, 10, 8},
	}
	for _, tc := range testCases {
		fmt.Println(tc)
		leavesLayerDistribution :=
			GenerateAdditiveTwoLayeredTreeSingleShare(trustees, tc.percentageThreshold,
				absoluteThreshold, tc.noOfSubsecrets)
		sum := 0
		for _, l := range leavesLayerDistribution {
			sum += l
		}
		if sum != trustees {
			t.Error("wrong number of shares", sum)
		}
	}
}
