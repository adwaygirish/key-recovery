package crypto

import (
	"fmt"
	"log"
	randm "math/rand"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func TestGenerateSalt(t *testing.T) {
	testCases := []struct {
		input    int
		expected int
	}{
		{16, 16},
		{32, 32},
		{64, 64},
	}
	// Iterate over test cases
	for _, tc := range testCases {
		// Call the function being tested
		result, _ := GenerateSalt(tc.input)

		// Check if the result matches the expected value
		if len(result) != tc.expected {
			t.Errorf("Length of GenerateSalt(%d) = %d; expected %d", tc.input,
				len(result), tc.expected)
		}
	}
}

func TestGetSHA256String(t *testing.T) {
	// Test cases
	testCases := []struct {
		input    string
		expected string
	}{
		{"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"world", "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"},
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, // Empty string
	}

	// Iterate over test cases
	for _, tc := range testCases {
		// Call the function being tested
		result := GetSHA256String(tc.input)

		// Check if the result matches the expected value
		if result != tc.expected {
			t.Errorf("CalculateSHA256(%q) = %q; expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestConvertKeyToBytes(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	fmt.Println(len(ConvertKeyToBytes(secretKey)))
	fmt.Println(ConvertKeyToBytes(secretKey))
}

func TestGetAES(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	bytesSecretKey := ConvertKeyToBytes(secretKey)
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	for i := 0; i < 100000; i++ {
		size := (rng.Intn(1000)) + 10
		// if size%16 == 0 {
		// 	size = size - 1
		// }
		// t.Log("sssssss", size)
		input, err := GenerateRandomBytes(size)
		if err != nil {
			t.Error(err)
		}
		ciphertext := GetAESEncryption(bytesSecretKey, input)
		plaintext, _, err := GetAESDecryption(bytesSecretKey, ciphertext)
		if err != nil {
			t.Error(err)
		}
		// fmt.Println(input, plaintext)
		if !CheckByteArrayEqual(input, plaintext) {
			t.Error("AES not working correctly", size)
			fmt.Println(len(plaintext), len(input))
		}
	}
}

func TestGetAESGCM(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	bytesSecretKey := ConvertKeyToBytes(secretKey)
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	for i := 0; i < 100000; i++ {
		size := (rng.Intn(1000)) + 10
		// if size%16 == 0 {
		// 	size = size - 1
		// }
		// t.Log("sssssss", size)
		input, err := GenerateRandomBytes(size)
		if err != nil {
			t.Error(err)
		}
		nonce, err := GenerateRandomBytes(12)
		if err != nil {
			t.Error(err)
		}
		authData, err := GenerateRandomBytes(27)
		if err != nil {
			t.Error(err)
		}
		ciphertext := GetAESGCMEncryption(bytesSecretKey, nonce, input, authData)
		plaintext, err := GetAESGCMDecryption(bytesSecretKey, nonce, ciphertext,
			authData)
		if err != nil {
			t.Error(err)
		}
		// fmt.Println(input, plaintext)
		if !CheckByteArrayEqual(input, plaintext) {
			t.Error("AES not working correctly", size)
			fmt.Println(len(plaintext), len(input))
		}
	}
}

func TestEncryptionLength(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)

	for i := 0; i < 10; i++ {
		nonce, err := GenerateSalt32()
		if err != nil {
			log.Fatalln(err)
		}
		x := rng.Intn(2000)
		val := g.Scalar().Pick(randSeedShares)
		shareVal := &share.PriShare{I: x, V: val}
		_, encryptionLength, err := GetRelevantEncryption(nonce, shareVal)
		if err != nil {
			log.Fatalln(err)
		}
		t.Log(encryptionLength)
	}
}

func TestMarkerData(t *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()

	// source := randm.NewSource(time.Now().UnixNano())
	// rng := randm.New(source)

	for i := 0; i < 10000; i++ {
		nonce, err := GenerateSalt32()
		if err != nil {
			log.Fatalln(err)
		}
		// x := rng.Intn(2000)
		val := g.Scalar().Pick(randSeedShares)
		shareVal := &share.PriShare{I: 0, V: val}
		_, _, err = GetRelevantEncryption(nonce, shareVal)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func TestConvertStringToBytes(t *testing.T) {
	testString := ""
	for i := 0; i < 240; i++ {
		testString = testString + "1"
	}
	for i := 0; i < 16; i++ {
		testString = testString + "0"
	}
	for i := 0; i < 10; i++ {
		testString = testString + "1"
	}
	byteOutput := ConvertBitStringToBytes(testString)
	fmt.Println(byteOutput[1])
}

// func TestKyber(t *testing.T) {
// 	g := edwards25519.NewBlakeSHA256Ed25519()
// 	randSeedShares := g.RandomStream()
// 	secretKey := g.Scalar().Pick(randSeedShares)
// 	temp := g.Scalar().Pick(randSeedShares)
// 	temp = temp.Set(secretKey)
// 	secretKey2 := g.Scalar().Pick(randSeedShares)
// 	fmt.Println(temp, secretKey, secretKey2)
// 	sumX := temp.Add(temp, secretKey2)
// 	fmt.Println(sumX, secretKey, secretKey2)
// 	fmt.Printf("%T \n", secretKey)
// 	n := 10
// 	th := n/2 + 1
// 	poly := share.NewPriPoly(g, th, secretKey, randSeedShares)
// 	shares := poly.Shares(n)
// 	for _, shareVal := range shares {
// 		fmt.Printf("%T \n", shareVal.V)
// 	}

// 	recovered, err := share.RecoverSecret(g, shares, th, n)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	if !recovered.Equal(poly.Secret()) {
// 		t.Fatal("recovered secret does not match initial value")
// 	}
// }
