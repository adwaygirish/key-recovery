package secret_binary_extension

import (
	"crypto/rand"
	"encoding/binary"
	"log"

	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
)

// This function for the simple case when there is no need for hierarchy
func GenerateShares(f shamir.Field, t, n int, secretKey []uint16,
	xUsedCoords *[]uint16) ([]shamir.PriShare, error) {
	f.InitializeTables()
	shareVals, _, err := f.SplitUniqueX(secretKey, n, t, xUsedCoords)
	if err != nil {
		return nil, err
	}
	return shareVals, nil
}

func GenerateSharesPercentage(f shamir.Field, thresholdPercentage int, n int,
	secretKey []uint16, xUsedCoords *[]uint16) ([]shamir.PriShare, error) {
	t := utils.FloorDivide(thresholdPercentage*n, 100)
	shareVals, err := GenerateShares(f, t, n, secretKey, xUsedCoords)
	if err != nil {
		return nil, err
	}
	return shareVals, nil
}

// This function provides the anonymity set
func GetDisAnonymitySet(f shamir.Field, n int, size int, maxSize int,
	shares []shamir.PriShare,
	xUsedCoords *[]uint16, relevantSize int) ([]shamir.PriShare, int) {
	f.InitializeTables()
	buf := make([]byte, 2)
	bufShare := make([]byte, 2*relevantSize)
	anonymitySetSize := size
	if n >= size {
		anonymitySetSize = n
	}
	anonymitySet := make([]shamir.PriShare, anonymitySetSize)
	copy(anonymitySet, shares)
	// When the number of shares is greater than the anonymity set (edge case),
	// the set of shares is the anonymity set
	if anonymitySetSize > n {
		for i := len(shares); i < anonymitySetSize; {
			if _, err := rand.Read(buf); err != nil {
				log.Fatalln(err)
			}
			x := binary.BigEndian.Uint16(buf)
			// We cannot use a zero x coordinate otherwise the y values
			// would be the intercepts i.e. the secret value itself.
			if x == 0 {
				continue
			}
			// Check if the x-coordinate has been already used
			exists := utils.IsInSliceUint16((*xUsedCoords), x)
			// If the x-coordinate repeats, do not store it again
			if exists {
				continue
			}
			(*xUsedCoords) = append((*xUsedCoords), x)
			if _, err := rand.Read(bufShare); err != nil {
				log.Fatalln(err)
			}
			y := shamir.BytesToUint16s(bufShare)
			anonymitySet[i] = shamir.PriShare{X: x, Y: y}
			i++
		}
	}
	return anonymitySet, anonymitySetSize
}
