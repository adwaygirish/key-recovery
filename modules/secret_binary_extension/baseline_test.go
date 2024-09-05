package secret_binary_extension

import (
	"fmt"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
	"log"
	"testing"
)

func TestGenerateSharesPercentage(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("testasdfghjklqwertyuaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)

	testCases := []struct {
		n                              int
		percentageLeavesLayerThreshold int
		a                              int
	}{
		{20, 100, 50},
		{20, 80, 50},
		{20, 90, 50},
		{20, 60, 50},
	}

	var xUsedCoords []uint16
	for _, tc := range testCases {
		shareVals, err := GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
			tc.n, secretKey, &xUsedCoords)
		if err != nil {
			log.Fatalln(err)
		}
		expectedThreshold := utils.FloorDivide(tc.percentageLeavesLayerThreshold*tc.n, 100)
		if len(shareVals) != tc.n {
			t.Error("wrong number of shares generated")
		}

		relevantShareVals := shareVals[:expectedThreshold]
		recovered, err := f.CombineUniqueX(relevantShareVals)

		if err != nil {
			log.Fatalln(err)
		}
		if !crypto_protocols.CheckByteArrayEqual(shamir.Uint16sToBytes(secretKey),
			shamir.Uint16sToBytes(recovered)) {
			t.Error("wrong threshold set")
		}
	}
}

func TestGetDisAnonymitySet(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("testasdfghjklqwertyuaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)

	testCases := []struct {
		n                              int
		percentageLeavesLayerThreshold int
		a                              int
	}{
		{20, 100, 50},
		{20, 80, 50},
		{20, 90, 50},
		{20, 60, 50},
	}

	var xUsedCoords []uint16
	for _, tc := range testCases {
		shareVals, err := GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
			tc.n, secretKey, &xUsedCoords)
		if err != nil {
			log.Fatalln(err)
		}
		anonPackets, _ := GetDisAnonymitySet(f, tc.n, tc.a, 200, shareVals,
			&xUsedCoords, len(secretKey))
		if len(anonPackets) != tc.a {
			t.Error("wrong length of anonymity set")
		}
	}
}

func TestBasicHashedSecretRecovery(t *testing.T) {
	var f shamir.Field
	f.InitializeTables()
	secretKey8 := []byte("testasdfghjklqwertyuaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secretKey := shamir.KeyBytesToKeyUint16s(secretKey8)
	secretKeyHash := crypto_protocols.GetSHA256(shamir.Uint16sToBytes(secretKey))

	testCases := []struct {
		n                              int
		percentageLeavesLayerThreshold int
		a                              int
	}{
		{20, 100, 30},
		{20, 80, 30},
		{20, 90, 30},
		{20, 60, 30},
	}

	var xUsedCoords []uint16
	for _, tc := range testCases {
		fmt.Println(tc)
		shareVals, err := GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
			tc.n, secretKey, &xUsedCoords)
		if err != nil {
			log.Fatalln(err)
		}
		anonPackets, _ := GetDisAnonymitySet(f, tc.n, tc.a, 200, shareVals,
			&xUsedCoords, len(secretKey))
		accessOrder := utils.GenerateIndicesSet(tc.a)
		utils.Shuffle(accessOrder)
		recovered, err := BasicHashedSecretRecoveryParallelized(f, anonPackets, accessOrder,
			secretKeyHash)
		if err != nil {
			log.Fatalln(err)
		}
		if !crypto_protocols.CheckRecSecretKeyBinExt(secretKeyHash,
			recovered) {
			t.Error("key not recovered", tc.percentageLeavesLayerThreshold)
		}
	}
}
