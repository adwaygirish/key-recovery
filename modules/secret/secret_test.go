package secret

import (
	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"
	"log"

	// randm "math/rand"
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// func BenchmarkBasicHashedSecretRecovery(b *testing.B) {
// 	g := edwards25519.NewBlakeSHA256Ed25519()
// 	randSeedShares := g.RandomStream()
// 	secretKey := g.Scalar().Pick(randSeedShares)
// 	// Convert the secret key to []byte
// 	byteSecret := crypto_protocols.ConvertKeyToBytes(secretKey)
// 	// Obtain the hash in []byte
// 	secretKeyHash := crypto_protocols.GetSHA256(byteSecret)
// 	configFilePath := "../configuration/config.yaml"
// 	cfg, err := configuration.NewSimulationConfig(configFilePath)
// 	if err != nil {
// 		fmt.Println("Error in accessing the config file")
// 	}
// 	type Parameter struct {
// 		Threshold  int
// 		SharesSize int
// 		AnonSize   int
// 	}
// 	var params []Parameter
// 	for _, t_data := range cfg.TrusteesData {
// 		t := t_data[0]
// 		n := t_data[1]
// 		for _, size := range cfg.AnonymitySetSize {
// 			params = append(params, Parameter{Threshold: t, SharesSize: n,
// 				AnonSize: size})
// 		}
// 	}
// 	maxSize := cfg.MaxAnonSetSize
// 	for _, p := range params {
// 		shares := GenerateShares(g, p.Threshold, p.SharesSize, secretKey, randSeedShares)
// 		anonymitySet, anonymitySetSize := GetDisAnonymitySet(g, p.Threshold,
// 			p.SharesSize, p.AnonSize,
// 			maxSize, randSeedShares, shares)
// 		for iter := 0; iter < cfg.Iterations; iter++ {
// 			accessOrder := utils.GenerateIndicesSet(anonymitySetSize)
// 			utils.Shuffle(accessOrder)
// 			b.ResetTimer()
// 			b.Run("", func(b *testing.B) {
// 				b.StartTimer() // Start the timer

// 				// Run the benchmark for b.N iterations
// 				for i := 0; i < b.N; i++ {
// 					BasicHashedSecretRecovery(g, p.Threshold, p.SharesSize, anonymitySetSize,
// 						anonymitySet, accessOrder, secretKeyHash, cfg.LargestShareSetSize)
// 				}
// 				b.StopTimer() // Stop the timer

// 				// Measure and print the time taken for this parameter combination
// 				b.Logf("Time taken for Threshold=%d, SharesSize=%d, AnonSize=%d",
// 					p.Threshold, p.SharesSize, p.AnonSize)
// 			})
// 		}
// 	}

// }

func TestBasicHashedSecretRecovery(t *testing.T) {
	testCases := []struct {
		n                              int
		a                              int
		absoluteThreshold              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
		percentageSubsecretsThreshold  int
	}{
		{20, 20, 4, 6, 15, 100},
	}

	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretKeyHash := crypto_protocols.GetSHA256(secretKeyBytes)
	maxSize := 200

	for _, tc := range testCases {

		fmt.Println("Trustees:", tc.n)
		fmt.Println("Anonymity:", tc.a)
		fmt.Println("Percentage", tc.percentageLeavesLayerThreshold)

		shareVals := GenerateSharesPercentage(g, tc.percentageLeavesLayerThreshold, tc.n,
			secretKey, randSeedShares)
		anonymityShareVals, _ := GetDisAnonymitySet(g,
			tc.n, tc.a, maxSize, randSeedShares, shareVals)

		accessOrder := utils.GenerateIndicesSet(tc.a)
		utils.Shuffle(accessOrder)

		// _, err := secret.BasicHashedSecretRecovery(g,
		// 	anonymityShareVals, accessOrder, secretKeyHash)
		_, err := BasicHashedSecretRecoveryParallelized(g,
			anonymityShareVals, accessOrder, secretKeyHash)
		if err != nil {
			log.Fatalln(err)
			continue
		}
	}
}

func TestGenerateFTOptDisShares(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	testCases := []struct {
		th int
		n  int
	}{
		{5, 3},
		{3, 5},
		{4, 10},
		{5, 12},
		{8, 15},
		{8, 20},
		{9, 17},
		{10, 19},
		{10, 25},
		{15, 40},
		{20, 50},
	}
	for _, tc := range testCases {
		flag, outputShares, outputSecretHashes, hashLevels, noOfShares, _, leavesData, outputSecretHashesSlice, _ :=
			GenerateFTOptDisShares(g, tc.th, tc.n, secretKey,
				randSeedShares, largestShareSetSize, smallestShareSetSize)
		if tc.th > tc.n {
			if flag == false {
				t.Log("More threshold than the number of shares detected")
			} else {
				t.Log("Did not detect more threshold than the number of shares")
			}
		} else {
			countShareSlice := 0
			noOfLevels := utils.GetLevels(tc.n, largestShareSetSize)
			for _, _ = range outputShares {
				countShareSlice++
			}
			if countShareSlice != len(outputSecretHashesSlice) {
				t.Error("Not the right number of shares and hashes generated; shares:",
					countShareSlice, "& hashes:",
					len(outputSecretHashesSlice), "}")
			}
			countHashSlice := 0
			for _, _ = range outputSecretHashes {
				countHashSlice++
			}
			if countHashSlice != len(outputSecretHashesSlice) {
				t.Error("Not the right number of shares and hashes generated; shares:",
					countShareSlice, "& hashes:",
					len(outputSecretHashesSlice), "}")
			}
			for hash1, level := range hashLevels {
				for hash2, sharesNum := range noOfShares {
					if hashLevels[hash2] == level {
						if noOfShares[hash1] != sharesNum && level != noOfLevels-1 {
							t.Error("Not the right number of shares for same levelled secrets; level:",
								level, noOfShares[hash1], noOfShares[hash2])
						}
					}
				}
			}
			if tc.n != len(leavesData) {
				t.Error("Not the right number of leaves generated required: ",
					tc.th, "& obtained:", len(leavesData), "}")
			}
			t.Log(tc.th, tc.n, len(leavesData), len(outputSecretHashesSlice))
		}
	}
}

func TestGetDisAnonymitySet(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	anonymitySetMaxSize := 150
	testCases := []struct {
		th int
		n  int
		a  int
	}{
		{3, 5, 10},
		{4, 10, 10},
		{5, 12, 20},
		{8, 15, 30},
		{8, 20, 20},
		{9, 17, 40},
		{10, 19, 50},
		{10, 25, 30},
		{15, 40, 50},
		{20, 50, 60},
	}
	for _, tc := range testCases {
		_, _, _, _, _, _, leavesData, _, _ :=
			GenerateFTOptDisShares(g, tc.th, tc.n, secretKey,
				randSeedShares, largestShareSetSize, smallestShareSetSize)
		anonymitySet, anonymitySetSize := GetDisAnonymitySet(g, tc.n, tc.a,
			anonymitySetMaxSize, randSeedShares, leavesData)
		if anonymitySetSize == tc.a && len(anonymitySet) == tc.a {
			t.Log("Anonymity Set correct for (threshold, number, anonymity set size)",
				tc.th, tc.n, tc.a, anonymitySetSize)
		} else {
			t.Error("Anonymity Set gone wrong for (threshold, number, anonymity set size)",
				tc.th, tc.n, tc.a, anonymitySetSize, len(anonymitySet))
		}
	}
}

func TestFTOptDisSecretRecovery(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	anonymitySetMaxSize := 150
	testCases := []struct {
		th int
		n  int
		a  int
	}{
		{4, 10, 10},
		{5, 12, 20},
		{8, 15, 30},
		{8, 20, 20},
		{9, 17, 20},
		{10, 19, 25},
		{10, 25, 30},
	}
	for _, tc := range testCases {
		_, _, _, _, _, _, leavesData, hashesSlice, secretKeyHash :=
			GenerateFTOptDisShares(g, tc.th, tc.n, secretKey,
				randSeedShares, largestShareSetSize, smallestShareSetSize)
		anonymitySet, anonymitySetSize := GetDisAnonymitySet(g, tc.n, tc.a,
			anonymitySetMaxSize, randSeedShares, leavesData)
		accessOrder := utils.GenerateIndicesSet(anonymitySetSize)
		utils.Shuffle(accessOrder)
		recoveredKey := FTOptDisSecretRecovery(g, tc.th, tc.n, anonymitySetSize,
			anonymitySet, accessOrder, secretKeyHash,
			largestShareSetSize, hashesSlice)
		if crypto_protocols.CheckHashesEqual(crypto_protocols.GetValSHA256(secretKey), crypto_protocols.GetValSHA256(recoveredKey)) {
			t.Log(tc.th, tc.n, tc.a, "Recovered")
		} else {
			t.Log(tc.th, tc.n, tc.a, "Not recovered")
		}
	}
}

func TestGenerateFTOptIndisShares(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	testCases := []struct {
		th int
		n  int
	}{
		{5, 3},
		{3, 5},
		{4, 10},
		{5, 12},
		{8, 15},
		{8, 20},
		{9, 17},
		{10, 19},
		{10, 25},
		{15, 40},
		{20, 50},
	}
	for _, tc := range testCases {
		outputShares, outputSecretHashes, _, hashLevels, noOfShares, _, leavesData, outputSecretHashesSlice, _, _, _, err :=
			GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
				randSeedShares, largestShareSetSize, smallestShareSetSize)
		if err != nil {
			t.Log(err)
		} else {
			countShareSlice := 0
			noOfLevels := utils.GetLevels(tc.n, largestShareSetSize)
			for _, _ = range outputShares {
				countShareSlice++
			}
			if countShareSlice != len(outputSecretHashesSlice) {
				t.Error("Not the right number of shares and hashes generated; shares:",
					countShareSlice, "& hashes:",
					len(outputSecretHashesSlice), "}")
			}
			countHashSlice := 0
			for _, _ = range outputSecretHashes {
				countHashSlice++
			}
			if countHashSlice != len(outputSecretHashesSlice) {
				t.Error("Not the right number of shares and hashes generated; shares:",
					countShareSlice, "& hashes:",
					len(outputSecretHashesSlice), "}")
			}
			for hash1, level := range hashLevels {
				for hash2, sharesNum := range noOfShares {
					if hashLevels[hash2] == level {
						if noOfShares[hash1] != sharesNum && level != noOfLevels-1 {
							t.Error("Not the right number of shares for same levelled secrets; level:",
								level, noOfShares[hash1], noOfShares[hash2])
						}
					}
				}
			}
			t.Log(tc.th, tc.n, len(leavesData), len(outputSecretHashesSlice))
		}
	}
}

func TestGetSharePackets(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	testCases := []struct {
		th int
		n  int
	}{
		{3, 5},
		{4, 10},
		{5, 12},
		{8, 15},
		{8, 20},
		{9, 17},
		{10, 19},
		{10, 25},
		{15, 40},
		{20, 50},
	}
	for _, tc := range testCases {
		outputShares, outputSecretHashes, noOfLevels, hashLevels, _, _, leavesData, _, secretKeyHash, parentSecrets, xUsedCoords, err :=
			GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
				randSeedShares, largestShareSetSize, smallestShareSetSize)
		// _, _, _, _, _, _, _, _, secretKeyHash, _, err :=
		// 	GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
		// 		randSeedShares, largestShareSetSize, smallestShareSetSize)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, _, err := GetSharePackets(g,
				randSeedShares, tc.n, tc.th, leavesData, secretKey, outputShares,
				outputSecretHashes, noOfLevels, hashLevels, secretKeyHash, parentSecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				t.Log(len(Packets), maxSharesPerPerson)
				var lengths2, lengths3, lengths4 []int
				for _, packet := range Packets {
					// lengths1 = append(lengths1, len(packet.Salts))
					lengths2 = append(lengths2, len(packet.RelevantHashes))
					lengths3 = append(lengths3, len(packet.ShareData))
					lengths4 = append(lengths4, len(packet.MarkerInfo))
				}
				// if !utils.CheckAllElementsSame(lengths1) {
				// 	t.Errorf("Not indistinguishable because of different number of salts")
				// }
				if !utils.CheckAllElementsSame(lengths2) {
					t.Errorf("Not indistinguishable because of different number of hashes")
				}
				if !utils.CheckAllElementsSame(lengths3) {
					t.Errorf("Not indistinguishable because of different number of share data")
				}
				if !utils.CheckAllElementsSame(lengths4) {
					t.Errorf("Not indistinguishable because of different number of marker info")
				}
				nonShareCount := 0
				shareCount := 0
				// Check if the cryptographic information generated is correct
				for _, packet := range Packets {
					sharesData := packet.ShareData
					relevantSalt := packet.Salt
					relevantHashes := packet.RelevantHashes
					relevantMarkerInfo := packet.MarkerInfo
					// fmt.Println(relevantMarkerInfo)
					for _, shareData := range sharesData {
						tempShare := shareData
						_, isExists := parentSecrets[tempShare]
						if !isExists {
							nonShareCount++
							continue
						}
						shareCount++
						for {
							// fmt.Println(tempShare)
							parentSecret := parentSecrets[tempShare]
							match1, match2, _, _, correctX, finalLevelObtained, err := crypto_protocols.GetIndisShareMatch(parentSecret.V, relevantHashes, relevantMarkerInfo, relevantSalt)
							if err != nil {
								t.Error(err)
							}
							if !match1 {
								t.Error("No hash found")
							}
							if !match2 {
								t.Error("No marker info found")
							}
							if match1 && match2 {
								if parentSecret.I != correctX {
									t.Error("Wrong X")
								}
								tempShare = parentSecret
							}
							if finalLevelObtained {
								break
							}
						}
					}
					// fmt.Println(relevantMarkerInfo)
					for _, markerInfo := range relevantMarkerInfo {
						if utils.ContainsZeros(markerInfo) {
							fmt.Println("Wrong packet", sharesData)
						}
					}
				}
				fmt.Println(len(leavesData), nonShareCount, shareCount)
			}
		}
	}
}

func TestGetAnonymityPackets(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	testCases := []struct {
		th int
		n  int
		a  int
	}{
		{3, 5, 10},
		{4, 10, 10},
		{5, 12, 20},
		{8, 15, 30},
		{8, 20, 20},
		{9, 17, 40},
		{10, 19, 50},
		{10, 25, 30},
		{15, 40, 50},
		{20, 50, 60},
	}
	for _, tc := range testCases {
		outputShares, outputSecretHashes, noOfLevels, hashLevels, _, _, leavesData, _, secretKeyHash, parentSecrets, xUsedCoords, err :=
			GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
				randSeedShares, largestShareSetSize, smallestShareSetSize)
		// _, _, _, _, _, _, _, _, secretKeyHash, _, err :=
		// 	GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
		// 		randSeedShares, largestShareSetSize, smallestShareSetSize)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, encryptionLength, err := GetSharePackets(g,
				randSeedShares, tc.n, tc.th, leavesData, secretKey, outputShares,
				outputSecretHashes, noOfLevels, hashLevels, secretKeyHash, parentSecrets, &xUsedCoords)
			if len(Packets) != tc.n {
				t.Error("Not the right number of share packets")
			}
			// If there is some error, then simply show the error
			if err != nil {
				t.Error(err)
			} else {
				// If the program runs in a fine,
				// then generate the anonymity packets
				anonymityPackets, err := GetAnonymityPackets(g, randSeedShares, Packets, tc.a, maxSharesPerPerson,
					noOfLevels, encryptionLength, &xUsedCoords)
				if err != nil {
					t.Error(err)
				} else {
					if len(anonymityPackets) != tc.a {
						t.Error("Not the right number of anonymity packets")
					}
				}
			}
		}
	}
}

func TestFTOptIndisSecretRecovery(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	largestShareSetSize := 5
	smallestShareSetSize := 3
	testCases := []struct {
		th int
		n  int
		a  int
	}{
		{3, 5, 10},
		{4, 10, 10},
		{5, 12, 15},
		{8, 15, 30},
		{8, 18, 20},
		// {9, 17, 40},
		// {10, 19, 50},
		// {10, 25, 30},
		// {15, 40, 50},
		// {20, 50, 60},
	}
	for _, tc := range testCases {
		outputShares, outputSecretHashes, noOfLevels, hashLevels, _, _, leavesData, _, secretKeyHash, parentSecrets, xUsedCoords, err := GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
			randSeedShares, largestShareSetSize, smallestShareSetSize)
		// _, _, _, _, _, _, _, _, secretKeyHash, _, err :=
		// 	GenerateFTOptIndisShares(g, tc.th, tc.n, secretKey,
		// 		randSeedShares, largestShareSetSize, smallestShareSetSize)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, encryptionLength, err := GetSharePackets(g,
				randSeedShares, tc.n, tc.th, leavesData, secretKey, outputShares,
				outputSecretHashes, noOfLevels, hashLevels, secretKeyHash, parentSecrets, &xUsedCoords)
			if len(Packets) != tc.n {
				t.Error("Not the right number of share packets")
			}
			// If there is some error, then simply show the error
			if err != nil {
				t.Error(err)
			} else {
				// If the program runs in a fine,
				// then generate the anonymity packets
				anonymityPackets, err := GetAnonymityPackets(g, randSeedShares, Packets, tc.a, maxSharesPerPerson,
					noOfLevels, encryptionLength, &xUsedCoords)
				// for xx, anonymityPacket := range anonymityPackets {
				// 	fmt.Println("xxxx", xx)
				// 	fmt.Println("ap", anonymityPacket.ShareData)
				// 	fmt.Println("ap", anonymityPacket.MarkerInfo)
				// }
				if err != nil {
					t.Error(err)
				} else {
					// if len(anonymityPackets) != tc.a {
					// 	t.Error("Not the right number of anonymity packets")
					// }
					accessOrder := utils.GenerateIndicesSet(tc.a)
					utils.Shuffle(accessOrder)
					fmt.Println(accessOrder)
					recoveredKey := FTOptIndisSecretRecovery(g,
						anonymityPackets, accessOrder,
						largestShareSetSize)
					// fmt.Println(recoveredKey)
					if !crypto_protocols.CheckValuesEqual(secretKey,
						recoveredKey) {
						t.Error("Secret key not recovered")
					}
				}
			}
		}
	}
}
