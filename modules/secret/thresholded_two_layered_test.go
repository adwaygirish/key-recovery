package secret

import (

	// randm "math/rand"

	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"
	"log"
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func TestGenerateTwoLayeredOptIndisShares(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)

	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		absoluteThreshold              int
		percentageLeavesLayerThreshold int
		percentageUpperLayerThreshold  int
	}{
		{20, 5, 4, 50, 100},
		{20, 5, 4, 60, 100},
		{20, 5, 4, 60, 80},
		{20, 5, 4, 60, 90},
		{20, 5, 4, 50, 90},
		{20, 5, 4, 50, 90},
		{20, 5, 4, 50, 60},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
				tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
				tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			if len(subsecrets) != int(tc.noOfSubsecrets) {
				t.Error("Not the correct number of subsecrets", len(subsecrets), (tc.percentageUpperLayerThreshold))
			}
			subsecretsTh := (tc.percentageUpperLayerThreshold * tc.noOfSubsecrets / 100)
			relevantSubset := subsecrets[:subsecretsTh]
			recovered, err := share.RecoverSecret(g, relevantSubset,
				subsecretsTh, subsecretsTh)

			if err != nil {
				fmt.Println(relevantSubset)
				log.Fatal(err)
			}
			if !recovered.Equal(secretKey) {
				log.Fatalln("recovered secret does not match initial value")
			}
			if len(xUsedCoords) != len(subsecrets)+len(leavesData)+1 {
				t.Error("Not the correct number of x-coordinates used")
			}
			sharesPerSubsecret := int(100 * tc.absoluteThreshold / tc.percentageLeavesLayerThreshold)
			if len(leavesData) != sharesPerSubsecret*tc.noOfSubsecrets {
				t.Error("Wrong number of leaves generated")
			}
			for _, value := range parentSubsecrets {
				flag := false
				for _, s := range subsecrets {
					if s.I == value.I && s.V == value.V {
						flag = true
						break
					}
				}
				if !flag {
					t.Error("Mistake in the parent subsecrets")
				}
			}
		}
	}
}

func TestGetSharePacketsTh(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	// absoluteThreshold := 5
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		absoluteThreshold              int
		percentageLeavesLayerThreshold int
		percentageUpperLayerThreshold  int
	}{
		{20, 5, 4, 50, 100},
		{20, 5, 4, 60, 100},
		{20, 5, 4, 60, 80},
		{20, 5, 4, 60, 90},
		{20, 5, 4, 50, 90},
		{20, 5, 4, 50, 90},
		{20, 5, 4, 50, 60},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err := GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
			tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
			tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, _, _, err := GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				// t.Log(len(Packets), maxSharesPerPerson)
				var lengths2, lengths3 []int
				for _, packet := range Packets {
					// lengths1 = append(lengths1, len(packet.Salts))
					lengths2 = append(lengths2, len(packet.RelevantEncryptions))
					lengths3 = append(lengths3, len(packet.ShareData))
				}

				if !utils.CheckAllElementsSame(lengths2) {
					t.Errorf("Not indistinguishable because of different number of hashes")
				}
				if !utils.CheckAllElementsSame(lengths3) {
					t.Errorf("Not indistinguishable because of different number of share data")
				}
				// Check if the cryptographic information generated is correct
				for _, packet := range Packets {
					sharesData := packet.ShareData
					relevantNonce := packet.Nonce
					relevantEncryptions := packet.RelevantEncryptions

					for _, shareData := range sharesData {
						tempShare := shareData
						_, isExists := parentSubsecrets[tempShare]
						if !isExists {
							continue
						}
						parentSubsecret := parentSubsecrets[tempShare]
						match1, correctX, _, err := crypto_protocols.GetThresholdedIndisShareMatch(parentSubsecret.V, relevantNonce, relevantEncryptions)
						if err != nil {
							t.Error(err)
						}
						if correctX != parentSubsecret.I {
							t.Error("Wrong x stored for subsecret")
						}
						if !match1 {
							t.Error("No encryption found")
						}

						match2, correctX2, _, err := crypto_protocols.GetThresholdedIndisShareMatch(secretKey, relevantNonce, relevantEncryptions)
						if err != nil {
							t.Error(err)
						}
						if !match2 {
							t.Error("No encryption found")
						}
						if correctX2 != 0 {
							t.Error("Secret key not present")
						}
					}
					// fmt.Println(relevantMarkerInfo)
					for _, markerInfo := range relevantEncryptions {
						if utils.ContainsZeros(markerInfo) {
							fmt.Println("Wrong packet", sharesData)
						}
					}
				}
				// fmt.Println(len(leavesData), nonShareCount, shareCount)
			}
		}
	}
}

func TestGetAnonymityPacketsTh(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	testCases := []struct {
		n                              int
		a                              int
		noOfSubsecrets                 int
		absoluteThreshold              int
		percentageLeavesLayerThreshold int
		percentageUpperLayerThreshold  int
	}{
		{20, 30, 5, 4, 50, 100},
		{20, 30, 5, 4, 60, 100},
		{20, 30, 5, 4, 60, 80},
		{20, 30, 5, 4, 60, 90},
		{20, 30, 5, 4, 50, 90},
		{20, 30, 5, 4, 50, 90},
		{20, 30, 5, 4, 50, 60},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err := GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
			tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
			tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, encryptionLength, err := GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				// If the program runs in a fine,
				// then generate the anonymity packets
				anonymityPackets, err := GetThresholdedAnonymityPackets(g,
					randSeedShares, Packets,
					tc.a, maxSharesPerPerson,
					&xUsedCoords, encryptionLength)
				if err != nil {
					t.Error(err)
				} else {
					if len(anonymityPackets) != tc.a {
						t.Error("Not the right number of anonymity packets")
					}
					var lengths2, lengths3 []int
					for _, packet := range Packets {
						// lengths1 = append(lengths1, len(packet.Salts))
						lengths2 = append(lengths2, len(packet.RelevantEncryptions))
						lengths3 = append(lengths3, len(packet.ShareData))
					}

					if !utils.CheckAllElementsSame(lengths2) {
						t.Errorf("Not indistinguishable because of different number of hashes")
					}
					if !utils.CheckAllElementsSame(lengths3) {
						t.Errorf("Not indistinguishable because of different number of share data")
					}
					// if !utils.CheckAllElementsSame(lengths4) {
					// 	t.Errorf("Not indistinguishable because of different number of share data")
					// }
				}
			}
		}
	}
}

func TestThOptUsedIndisSecretRecovery(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	testCases := []struct {
		n                              int
		a                              int
		noOfSubsecrets                 int
		absoluteThreshold              int
		percentageLeavesLayerThreshold int
		percentageUpperLayerThreshold  int
	}{
		{20, 30, 5, 4, 50, 100},
		{20, 30, 5, 4, 60, 100},
		{20, 30, 5, 4, 60, 80},
		{20, 30, 5, 4, 60, 90},
		{20, 30, 5, 4, 50, 90},
		{20, 30, 5, 4, 50, 90},
		{20, 30, 5, 4, 50, 60},
		{22, 30, 5, 4, 50, 100},
		{24, 30, 5, 4, 50, 60},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err := GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
			tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
			tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, encryptionLength, err := GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				// If the program runs in a fine,
				// then generate the anonymity packets
				anonymityPackets, err := GetThresholdedAnonymityPackets(g,
					randSeedShares, Packets, tc.a, maxSharesPerPerson,
					&xUsedCoords, encryptionLength)
				if err != nil {
					t.Error(err)
				} else {
					accessOrder := utils.GenerateIndicesSet(tc.a)
					utils.Shuffle(accessOrder)
					recoveredKey := ThOptUsedIndisSecretRecovery(g,
						randSeedShares,
						anonymityPackets, accessOrder,
						tc.absoluteThreshold)
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
