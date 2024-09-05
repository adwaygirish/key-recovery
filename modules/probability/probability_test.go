package probability

import (
	"fmt"
	"key_recovery/modules/utils"
	"testing"
)

func TestGetSimpleProbability(t *testing.T) {
	testCases := []struct {
		s    int
		l    int
		th   int
		tr   int
		a    int
		lsss int
		ssss int
		lpn  int
	}{
		{1, 2, 50, 100, 100, 5, 2, 10},
		{1, 2, 50, 30, 100, 5, 2, 10},
	}
	for _, tc := range testCases {
		results, results_anon, err := GetSimpleProbability(tc.s, tc.l, tc.th, tc.tr, tc.a,
			tc.lsss, tc.ssss, tc.lpn)
		if err != nil {
			t.Error(err)
		} else {
			vals1, vals2 := 0, 0
			for k, v := range results {
				vals1++
				if v != 0 {
					t.Log(k, v)
				}
			}
			for k, v := range results_anon {
				vals2++
				if v != 0 {
					t.Log(k, v)
				}
			}
			t.Log(vals1, vals2)
		}
	}
}

func TestCreatePeoplePackets(t *testing.T) {
	testCases := []struct {
		s   int
		l   int
		th  int
		tr  int
		a   int
		lpn int
	}{
		{10, 2, 50, 100, 100, 10},
	}
	for _, tc := range testCases {
		output, layerWiseChildren, err := CreatePeoplePackets(tc.l, tc.th,
			tc.tr, tc.a, tc.lpn)
		if err != nil {
			t.Error(err)
		} else {
			t.Log(output)
			t.Log(layerWiseChildren)
			// for k, v := range results {
			// 	if v != 0 {
			// 		t.Log(k, v)
			// 	}
			// }
		}
	}
}

// func TestTotalHintedTRecovery(t *testing.T) {
// 	// testCases := GenerateTestCasesHintedT(1000)
// 	// for _, tc := range testCases {
// 	// 	fmt.Println(tc)
// 	// 	results, results_anon, err :=
// 	// 		probability.GetHintedProbabilityCDF(simulations, tc.th, tc.tr, tc.a)
// 	// 	if err != nil {
// 	// 		log.Fatal(err)
// 	// 	} else {
// 	// 		// Get the data that has to be put into the csv file
// 	// 		data, sum1, sum2 := FormDataForCSV(results, results_anon)
// 	// 		fmt.Println(tc.th, sum1, sum2)
// 	// 		// Set the name of the file according to the parameters used for
// 	// 		// generating the result
// 	// 		csvFileName := GenerateFileName(csvDir, rng.Intn(10000), tc)
// 	// 		fmt.Println(csvFileName)
// 	// 		err, _ := files.CreateFile(csvFileName)
// 	// 		if err != nil {
// 	// 			log.Fatal("Error in writing to the CSV file", err)
// 	// 		}
// 	// 		err = files.WriteToCSVFile(csvFileName, data)
// 	// 		if err != nil {
// 	// 			log.Fatal("Error in writing to the CSV file", err)
// 	// 		}
// 	// 	}
// 	// }
// 	noOfSimulations := 10
// 	testCases := []struct {
// 		n                              int
// 		a                              int
// 		absoluteThreshold              int
// 		noOfSubsecrets                 int
// 		percentageLeavesLayerThreshold int
// 		noOfHints                      int
// 	}{
// 		{20, 50, 4, 6, 60, 5},
// 	}
// 	for _, tc := range testCases {
// 		_, _, err := GetHintedTProbabilityFixedThTotalCDF(noOfSimulations,
// 			2, tc.percentageLeavesLayerThreshold, tc.n, tc.a, tc.absoluteThreshold,
// 			tc.noOfSubsecrets, tc.noOfHints)
// 		if err != nil {
// 			log.Fatalln("couldn't run hinted simulation")
// 		}
// 	}
// }

func TestRecoverySimulation(t *testing.T) {
	// Generate the data over which the simulations will be run
	// simulationsDist := 1000
	// simulationsRun := 10
	tc := ProbEval{2, 66, 3, 3, 2, 2}
	fmt.Println(tc)
	// layerWiseChildren := make(map[int]map[int][]int)
	// layerWiseChildren[0] = make(map[int][]int)
	// layerWiseChildren[0][0] = []int{1, 2}
	// layerWiseChildren[1] = make(map[int][]int)
	// layerWiseChildren[1][1] = []int{3, 4, 5}
	// layerWiseChildren[1][2] = []int{3, 4, 5}
	sharesNum := utils.FloorDivide((tc.at * 100), tc.th)
	_, layerWiseChildren, _ := CreatePeoplePacketsFixedTh(tc.l,
		tc.th, tc.tr, tc.a, tc.hlpn, sharesNum)
	fmt.Println(layerWiseChildren)
	peoplePacketsComb := make([][][]int, 0)
	tempPacket := make([][]int, 0)
	listShares := []int{3, 4, 5, 6, 7, 8}
	for i1 := 0; i1 < len(listShares)-1; i1++ {
		for i2 := i1 + 1; i2 < len(listShares); i2++ {
			tempPacket = append(tempPacket, []int{listShares[i1], listShares[i2]})
		}
	}
	fmt.Println(peoplePacketsComb)
	fmt.Println(tempPacket)

	for _, t1 := range tempPacket {
		for _, t2 := range tempPacket {
			if len(utils.GetIntersection(t1, t2)) == 0 {
				for _, t3 := range tempPacket {
					if len(utils.GetIntersection(t1, t3)) == 0 &&
						len(utils.GetIntersection(t2, t3)) == 0 {
						peoplePacketsComb = append(peoplePacketsComb, [][]int{t1, t2, t3})
					}
				}
			}
		}
	}

	results := make(map[int]int)
	results_anon := make(map[int]int)
	for i := 0; i < tc.a; i++ {
		results[i+1] = 0
		results_anon[i+1] = 0
	}

	accessOrders := [][]int{
		// []int{0, 1, 2},
		[]int{0, 2, 1},
		// []int{1, 0, 2},
		// []int{1, 2, 0},
		// []int{2, 0, 1},
		// []int{2, 1, 0},
	}

	for _, peoplePackets := range peoplePacketsComb {
		fmt.Println(peoplePackets)
	}

	for _, peoplePackets := range peoplePacketsComb {
		fmt.Println("----------------------------------")
		fmt.Println(peoplePackets)
		for _, accessOrder := range accessOrders {
			fmt.Println("***********************************")
			fmt.Println(accessOrder)
			fmt.Println("***********************************")
			var obtainedShares, usedShares, obtainedSubsecrets,
				usedSubsecrets, peopleContacted []int
			usedSharesMap := make(map[int][]int)
			for _, a := range accessOrder {
				fmt.Println("^^^^^ Accessed ^^^^^^^^", a)
				// fmt.Println("contacted", a)
				obtainedShares = append(obtainedShares, peoplePackets[a]...)
				peopleContacted = append(peopleContacted, a)
				// Shares obtained from the most recently contacted person
				newShares := peoplePackets[a]
				// Check with the already reconstructed subsecrets
				CheckAlreadyUsedShares(usedSharesMap, newShares,
					layerWiseChildren[tc.l-1], &usedShares)
				relevantData := utils.FindDifference(obtainedShares, usedShares)
				// First recover the secret in the leaves layer
				isPenRecovered := CheckLeavesRecovery(relevantData,
					layerWiseChildren[tc.l-1], tc.at, &usedShares,
					&obtainedSubsecrets, usedSharesMap)
				fmt.Println("recovery update subsecrets", obtainedSubsecrets)
				fmt.Println("used shares update", usedShares)
				fmt.Println("obtained shares update", obtainedShares)
				fmt.Println("used shares map", usedSharesMap)
				// If you recover some subsecret (from the penultimate layer),
				// only then run the secret recovery for the layer above
				if isPenRecovered {
					isSecretRecovered, secretsRecovered :=
						CheckAboveLayer(tc.hlpn, &obtainedSubsecrets,
							&usedSubsecrets, layerWiseChildren, tc.l)
					if isSecretRecovered {
						// fmt.Println("ss")
						if utils.IsInSlice(secretsRecovered, 0) {
							// If the secret key has been recovered,
							// then break the loop
							totalNum := len(peopleContacted)
							results_anon[totalNum] += 1
							// This gives the number of trustees
							// This gives the number of elements which have the value
							// less than the variable trustees
							trusteesNum := utils.CountLessThan(peopleContacted, tc.tr)
							results[trusteesNum] += 1
							break
						}
					}
				}
			}
			fmt.Println(results_anon)
		}
	}
	fmt.Println(results_anon)
}
