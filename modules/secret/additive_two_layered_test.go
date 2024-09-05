package secret

import (

	// randm "math/rand"

	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestGenerateAddtiveTwoLayeredOptIndisShares(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	absoluteThreshold := 5
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
			GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
				secretKey, randSeedShares, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			sharesSum := g.Scalar().Pick(randSeedShares)
			sharesSum = sharesSum.Set(subsecrets[0])
			// fmt.Println("-----", sharesSum)
			for _, subsecret := range subsecrets[1:] {
				sharesSum = sharesSum.Add(sharesSum, subsecret)
			}
			if !sharesSum.Equal(secretKey) {
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
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
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
		{20, 5, 60},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
				secretKey, randSeedShares, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			Packets, maxSharesPerPerson, err := GetAdditiveSharePackets(g,
				randSeedShares, secretKey, tc.n, absoluteThreshold,
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
						_, isExists := parentSubsecrets[shareData]
						if !isExists {
							continue
						}
						// Check that the subsecret is stored within the relevant hashes
						if !crypto_protocols.GetSaltedKeyMembership(relevantHashes,
							relevantSalt, parentSubsecrets[shareData]) {
							t.Error("susbecret not included")
						}
						// Check that the main secret is stored within the relevant hashes
						if !crypto_protocols.GetSaltedKeyMembership(relevantHashes,
							relevantSalt, parentSubsecrets[shareData]) {
							t.Error("secret not included")
						}
					}
				}
			}
		}
	}
}

func TestGetAdditiveAnonymityPackets(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	absoluteThreshold := 4
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
		a                              int
	}{
		// {8, 10, 50, 20},
		// {20, 10, 50, 30},
		// {20, 20, 50, 30},
		// {22, 10, 50, 30},
		{20, 5, 60, 30},
	}
	for _, tc := range testCases {
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
				secretKey, randSeedShares, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			sharePackets, maxSharesPerPerson, err := GetAdditiveSharePackets(g,
				randSeedShares, secretKey, tc.n, absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				anonymityPackets, err := GetAdditiveAnonymityPackets(g,
					randSeedShares, sharePackets,
					tc.a, maxSharesPerPerson,
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
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	absoluteThreshold := 4
	testCases := []struct {
		n                              int
		noOfSubsecrets                 int
		percentageLeavesLayerThreshold int
		a                              int
	}{
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
	for _, tc := range testCases {
		fmt.Println(tc)
		subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
			GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
				secretKey, randSeedShares, absoluteThreshold,
				tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)
		if err != nil {
			t.Log(err)
		} else {
			sharePackets, maxSharesPerPerson, err := GetAdditiveSharePackets(g,
				randSeedShares, secretKey, tc.n, absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)
			if err != nil {
				t.Error(err)
			} else {
				anonymityPackets, err := GetAdditiveAnonymityPackets(g,
					randSeedShares, sharePackets,
					tc.a, maxSharesPerPerson,
					&xUsedCoords)
				if err != nil {
					t.Error(err)
				} else {
					accessOrder := utils.GenerateIndicesSet(tc.a)
					utils.Shuffle(accessOrder)
					fmt.Println(accessOrder)
					recoveredKey := AdditiveOptUsedIndisSecretRecovery(g,
						randSeedShares,
						anonymityPackets, accessOrder,
						absoluteThreshold)
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
