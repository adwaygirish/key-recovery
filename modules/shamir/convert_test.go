package shamir

import (
	"crypto/subtle"
	"fmt"
	"testing"
)

func TestKeyBytesToAESKeyUint16s(t *testing.T) {
	testCases := [][]byte{[]byte("test"), []byte("tests"), []byte("testsss"),
		[]byte("asdfghjklqwertyuio")}
	for _, tc := range testCases {
		k := KeyBytesToAESKeyUint16s(tc)
		fmt.Println(len(k))
		for i := 0; i < len(k); i++ {
			if len(k[i])%8 != 0 {
				t.Error("wrong length for AES", len(k[i]))
			}
		}
		k2 := AESKeyUint16sToKeyBytes(k)
		if subtle.ConstantTimeCompare(k2, tc) != 1 {
			t.Error("wrong recovery", tc, k2)
		}
	}
}

func TestKeyBytesToKeyUint16s(t *testing.T) {
	testCases := [][]byte{[]byte("test"), []byte("tests"), []byte("testsss"),
		[]byte("asdfghjklqwertyuio")}
	for _, tc := range testCases {
		k := KeyBytesToKeyUint16s(tc)
		fmt.Println(len(tc), len(k))
		k2 := KeyUint16sToKeyBytes(k)
		if subtle.ConstantTimeCompare(k2, tc) != 1 {
			t.Error("wrong recovery", tc, k2)
		}
	}
}
