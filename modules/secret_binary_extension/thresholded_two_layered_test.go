package secret_binary_extension

import (

	// randm "math/rand"

	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
	"log"
	"testing"
)

func TestGenerateThresholdedTwoLayeredOptIndisShares(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("testasdfghjklqwertyu")
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKey8)

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
		fmt.Println(tc)
		subsecrets, leavesData, parentSubsecrets, _, err :=
			GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
				tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
				tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			if len(subsecrets[0]) != int(tc.noOfSubsecrets) {
				t.Error("Not the correct number of subsecrets", len(subsecrets), (tc.percentageUpperLayerThreshold))
			}
			subsecretsTh := utils.CeilDivide(tc.percentageUpperLayerThreshold*tc.noOfSubsecrets, 100)
			for ind1 := 0; ind1 < len(secretKey); ind1++ {
				relevantSubset := subsecrets[ind1][:subsecretsTh]
				recovered, err := f.CombineUniqueX(relevantSubset)

				if err != nil {
					fmt.Println(relevantSubset)
					log.Fatal(err)
				}
				for ind, r := range recovered {
					if r != secretKey[ind1][ind] {
						fmt.Println("no")
					}
				}
				if !crypto_protocols.CheckByteArrayEqual(shamir.Uint16sToBytes(recovered), shamir.Uint16sToBytes(secretKey[ind1])) {
					log.Fatalln("recovered secret does not match initial value")
				}
				// if len(xUsedCoords) != len(subsecrets)+len(leavesData)+1 {
				// 	t.Error("Not the correct number of x-coordinates used")
				// }
				sharesPerSubsecret := int(100 * tc.absoluteThreshold / tc.percentageLeavesLayerThreshold)
				if len(leavesData[ind1]) != sharesPerSubsecret*tc.noOfSubsecrets {
					t.Error("Wrong number of leaves generated", len(leavesData[ind1]))
					fmt.Println(leavesData[ind1])
				}
				for _, value := range parentSubsecrets[ind1] {
					flag := false
					for _, s := range subsecrets[ind1] {
						if s.X == value.X &&
							crypto_protocols.CheckByteArrayEqual(shamir.Uint16sToBytes(s.Y), shamir.Uint16sToBytes(value.Y)) {
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
}

func TestGetThresholdedSharePackets(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("testasdfghjklqwertyu")
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKey8)
	fmt.Println(secretKey)
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
			GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
				tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
				tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, _, _, err := GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				// t.Log(len(Packets), maxSharesPerPerson)
				var lengths2, lengths3 []int
				for ind1 := 0; ind1 < len(secretKey); ind1++ {
					for _, packet := range Packets {
						// lengths1 = append(lengths1, len(packet.Salts))
						lengths2 = append(lengths2, len(packet.RelevantEncryptions[ind1]))
						lengths3 = append(lengths3, len(packet.ShareData[ind1]))
					}

					if !utils.CheckAllElementsSame(lengths2) {
						t.Errorf("Not indistinguishable because of different number of hashes")
					}
					if !utils.CheckAllElementsSame(lengths3) {
						t.Errorf("Not indistinguishable because of different number of share data")
					}
					// Check if the cryptographic information generated is correct
					for _, packet := range Packets {
						sharesData := packet.ShareData[ind1]
						relevantNonce := packet.Nonce
						relevantEncryptions := packet.RelevantEncryptions[ind1]

						for _, shareData := range sharesData {
							tempShare := shareData
							_, isExists := parentSubsecrets[ind1][tempShare.X]
							if !isExists {
								continue
							}
							parentSubsecret := parentSubsecrets[ind1][tempShare.X]
							match1, correctX, _, err := crypto_protocols.GetThresholdedIndisShareMatchBinExt(parentSubsecret.Y, relevantNonce, relevantEncryptions)
							if err != nil {
								t.Error(err)
							}
							if correctX != parentSubsecret.X {
								t.Error("Wrong x stored for subsecret")
							}
							if !match1 {
								t.Error("No encryption found")
							}

							match2, correctX2, _, err := crypto_protocols.GetThresholdedIndisShareMatchBinExt(secretKey[ind1], relevantNonce, relevantEncryptions)
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
				}
				// fmt.Println(len(leavesData), nonShareCount, shareCount)
			}
		}
	}
}

func TestGetThresholdedAnonymityPackets(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("testasdfghjklqwertyu")
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKey8)
	fmt.Println(secretKey)
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		absoluteThreshold              int
		percentageLeavesLayerThreshold int
		percentageUpperLayerThreshold  int
		a                              int
	}{
		{20, 5, 4, 50, 100, 50},
		{20, 5, 4, 60, 100, 50},
		{20, 5, 4, 60, 80, 50},
		{20, 5, 4, 60, 90, 50},
		{20, 5, 4, 50, 90, 50},
		{20, 5, 4, 50, 90, 50},
		{20, 5, 4, 50, 60, 50},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
				tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
				tc.percentageUpperLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, encryptionLength, err := GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				// If the program runs in a fine,
				// then generate the anonymity packets
				anonymityPackets, err := GetThresholdedAnonymityPackets(
					Packets, tc.a, maxSharesPerPerson,
					len(secretKey[0]), len(secretKey),
					&xUsedCoords, encryptionLength)
				if err != nil {
					t.Error(err)
				} else {
					if len(anonymityPackets) != tc.a {
						t.Error("Not the right number of anonymity packets")
					}
					var lengths2, lengths3 []int
					for ind1 := 0; ind1 < len(secretKey); ind1++ {
						for _, packet := range Packets {
							// lengths1 = append(lengths1, len(packet.Salts))
							lengths2 = append(lengths2, len(packet.RelevantEncryptions[ind1]))
							lengths3 = append(lengths3, len(packet.ShareData[ind1]))
						}
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

func TestThresholdedOptUsedIndisSecretRecovery(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	// secretKey8 := []byte("testasdfghjklqwertyu")
	secretKey8 := []byte("testasdfghjklqwertyuaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKey8)
	// fmt.Println(secretKey)
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		absoluteThreshold              int
		percentageLeavesLayerThreshold int
		percentageUpperLayerThreshold  int
		a                              int
	}{
		{20, 5, 4, 50, 100, 50},
		{20, 5, 4, 60, 100, 50},
		{20, 5, 4, 60, 80, 50},
		{20, 5, 4, 60, 90, 50},
		{20, 5, 4, 50, 90, 50},
		{20, 5, 4, 50, 90, 50},
		{20, 5, 4, 50, 60, 50},
	}
	for iter := 0; iter < 20; iter++ {
		for _, tc := range testCases {
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageUpperLayerThreshold)
			if err != nil {
				t.Log(err)
			} else {
				Packets, maxSharesPerPerson, encryptionLength, err := GetThresholdedSharePackets(f,
					secretKey, tc.n, tc.absoluteThreshold,
					leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
				if err != nil {
					t.Error(err)
				} else {
					// If the program runs in a fine,
					// then generate the anonymity packets
					anonymityPackets, err := GetThresholdedAnonymityPackets(
						Packets, tc.a, maxSharesPerPerson,
						len(secretKey[0]), len(secretKey),
						&xUsedCoords, encryptionLength)
					if err != nil {
						t.Error(err)
					} else {
						accessOrder := utils.GenerateIndicesSet(tc.a)
						utils.Shuffle(accessOrder)
						recoveredKey := ThOptUsedIndisSecretRecoveryParallelized(f,
							anonymityPackets, accessOrder,
							tc.absoluteThreshold)
						recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
						if !crypto_protocols.CheckByteArrayEqual(secretKey8, recoveredSecretKey) {
							t.Error("wrong recovery")
						}
						fmt.Println(recoveredKey)
						// fmt.Println(recoveredKey)
						// if !crypto_protocols.Check(secretKey,
						// 	recoveredKey) {
						// 	t.Error("Secret key not recovered")
						// }
					}
				}
			}
		}
	}
}
