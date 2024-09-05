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

func TestGenerateRandomXShares(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()

	key1 := []byte("test")
	key2 := []byte("best")
	key1_16 := shamir.BytesToUint16s(key1)
	key2_16 := shamir.BytesToUint16s(key2)

	xUsedCoords := make([]uint16, 0)
	testCases := []struct {
		n int
		t int
	}{
		{5, 3},
		{10, 6},
	}
	count := 0
	for _, tc := range testCases {
		s, err := GenerateRandomXShares(f, tc.t, tc.n, key1_16, &xUsedCoords)
		fmt.Println(s)
		if err != nil {
			log.Fatalln(err)
		}
		count += tc.n
		if count != len(xUsedCoords) {
			t.Error("wrong number of shares", tc.n, tc.t)
		}
		s, err = GenerateRandomXShares(f, tc.t, tc.n, key2_16, &xUsedCoords)
		fmt.Println(s)
		if err != nil {
			log.Fatalln(err)
		}
		count += tc.n
		if count != len(xUsedCoords) {
			t.Error("wrong number of shares", tc.n, tc.t)
		}
	}
}

func TestGenerateAdditiveTwoLayeredOptIndisShares(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("test")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)
	absoluteThreshold := 4
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
	}{
		{8, 10, 50},
		{20, 10, 50},
		{20, 20, 50},
		{22, 10, 50},
		{20, 5, 100},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, _, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
				secretKey, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			sharesSum := make([]uint16, len(secretKey))
			for _, subsecret := range subsecrets {
				tempSum, err := shamir.SliceAdd(sharesSum, subsecret)
				if err != nil {
					log.Fatalln(err)
				}
				sharesSum = tempSum
			}
			if !crypto_protocols.CompareUint16s(secretKey, sharesSum) {
				t.Error("Subsecrets not generated correctly")
				continue
			}
			noOfShares := (absoluteThreshold * 100) / tc.percentageLeavesLayerThreshold
			if len(leavesData) != noOfShares*tc.noOfSubsecrets {
				t.Error("Not the correct no. of leaves generated")
				continue
			}
			if len(xUsedCoords) != len(leavesData) {
				t.Error("Not the correct no. of x coordinates used")
				continue
			}
			t.Log(tc.n, tc.percentageLeavesLayerThreshold)
		}
	}
}

func TestGetAdditiveSharePackets(t *testing.T) {
	var f shamir.Field
	// f.InitializeTables()
	secretKey8 := []byte("test")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)
	absoluteThreshold := 4
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
	}{
		{8, 10, 50},
		{20, 10, 50},
		{20, 20, 50},
		{22, 10, 50},
		{20, 5, 100},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
				secretKey, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, err := GetAdditiveSharePackets(f,
				secretKey, tc.n, absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				t.Log(len(Packets), maxSharesPerPerson)
				var lengths2, lengths3 []int
				for _, packet := range Packets {
					lengths2 = append(lengths2, len(packet.RelevantHashes))
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
					relevantSalt := packet.Salt
					relevantHashes := packet.RelevantHashes
					for _, shareData := range sharesData {
						_, isExists := parentSubsecrets[shareData.X]
						if !isExists {
							continue
						}
						// Check that the subsecret is stored within the relevant hashes
						if !crypto_protocols.GetSaltedKeyMembershipBinExt(relevantHashes,
							relevantSalt, parentSubsecrets[shareData.X]) {
							t.Error("susbecret not included")
						}
						// Check that the main secret is stored within the relevant hashes
						if !crypto_protocols.GetSaltedKeyMembershipBinExt(relevantHashes,
							relevantSalt, parentSubsecrets[shareData.X]) {
							t.Error("secret not included")
						}
					}
				}
			}
		}
	}
}

func TestGetAdditiveAnonymityPackets(t *testing.T) {
	var f shamir.Field
	// f.InitializeTables()
	secretKey8 := []byte("test")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)
	absoluteThreshold := 4
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
		a                              int
	}{
		{8, 10, 50, 20},
		{20, 10, 50, 40},
		{20, 20, 50, 50},
		{22, 10, 50, 50},
		{20, 5, 100, 50},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
				secretKey, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			sharePackets, maxSharesPerPerson, err := GetAdditiveSharePackets(f,
				secretKey, tc.n, absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				anonymityPackets, err := GetAdditiveAnonymityPackets(
					sharePackets, tc.a, maxSharesPerPerson, len(secretKey),
					&xUsedCoords)
				if err != nil {
					t.Error(err)
				} else {
					if len(anonymityPackets) != tc.a {
						t.Error(len(anonymityPackets))
						t.Error("Not the right number of anonymity packets")
					}
					for _, p := range sharePackets {
						for _, ap := range anonymityPackets {
							if len(p.RelevantHashes) != len(ap.RelevantHashes) {
								fmt.Println(len(p.RelevantHashes), len(ap.RelevantHashes), maxSharesPerPerson)
								fmt.Println("Packets are distinguishable")
							}
						}
					}
				}
			}
		}
	}
}

func TestAdditiveOptIndisSecretRecovery(t *testing.T) {
	var f shamir.Field
	// f.InitializeTables()
	secretKey8 := []byte("test")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)
	absoluteThreshold := 4
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
		a                              int
	}{
		{5, 5, 50, 10},
		{8, 5, 50, 10},
		{20, 5, 50, 20},
		{20, 5, 60, 20},
		{20, 5, 70, 20},
		{20, 5, 80, 20},
		{20, 5, 50, 30},
		{20, 5, 50, 40},
		{22, 5, 50, 50},
		{20, 5, 50, 60},
	}
	// for _, tc := range testCases {
	// 	fmt.Println(tc)
	// 	subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
	// 		GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
	// 			secretKey, absoluteThreshold,
	// 			tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
	// 	if err != nil {
	// 		t.Log(err)
	// 	} else {
	// 		sharePackets, maxSharesPerPerson, err := GetAdditiveSharePackets(f,
	// 			secretKey, tc.n, absoluteThreshold,
	// 			leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
	// 		if err != nil {
	// 			t.Error(err)
	// 		} else {
	// 			anonymityPackets, err := GetAdditiveAnonymityPackets(
	// 				sharePackets,
	// 				tc.a, maxSharesPerPerson, len(secretKey),
	// 				&xUsedCoords)
	// 			if err != nil {
	// 				t.Error(err)
	// 			} else {
	// 				accessOrder := utils.GenerateIndicesSet(tc.a)
	// 				utils.Shuffle(accessOrder)
	// 				fmt.Println(accessOrder)
	// 				recoveredKey := AdditiveOptUsedIndisSecretRecovery(f,
	// 					anonymityPackets, accessOrder,
	// 					absoluteThreshold)
	// 				// fmt.Println(recoveredKey)
	// 				if !crypto_protocols.CompareUint16s(secretKey,
	// 					recoveredKey) {
	// 					t.Error("Secret key not recovered")
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	for _, tc := range testCases {
		fmt.Println(tc)
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
				secretKey, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			sharePackets, maxSharesPerPerson, err := GetAdditiveSharePackets(f,
				secretKey, tc.n, absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				anonymityPackets, err := GetAdditiveAnonymityPackets(
					sharePackets,
					tc.a, maxSharesPerPerson, len(secretKey),
					&xUsedCoords)
				if err != nil {
					t.Error(err)
				} else {
					accessOrder := utils.GenerateIndicesSet(tc.a)
					utils.Shuffle(accessOrder)
					// accessOrder := []int{3, 7, 5, 2, 1, 0, 8, 4, 6, 9}
					fmt.Println(accessOrder)
					recoveredKey := AdditiveOptUsedIndisSecretRecoveryParallelized(f,
						anonymityPackets, accessOrder,
						absoluteThreshold)
					// fmt.Println(recoveredKey)
					if !crypto_protocols.CompareUint16s(secretKey,
						recoveredKey) {
						t.Error("Secret key not recovered")
					}
				}
			}
		}
	}
}
