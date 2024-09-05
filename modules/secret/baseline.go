package secret

import (
	"crypto/cipher"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// This function for the simple case when there is no need for hierarchy
func GenerateShares(g kyber.Group, t, n int, secretKey kyber.Scalar,
	rand cipher.Stream) []*share.PriShare {
	polynomial := share.NewPriPoly(g, t, secretKey, rand)
	return polynomial.Shares(n)
}

func GenerateSharesPercentage(g kyber.Group, thresholdPercentage int, n int,
	secretKey kyber.Scalar, rand cipher.Stream) []*share.PriShare {
	t := (thresholdPercentage * n) / 100
	return GenerateShares(g, t, n, secretKey, rand)
}

// This function provides the anonymity set
func GetDisAnonymitySet(g kyber.Group, n int, size int, maxSize int,
	rand cipher.Stream, shares []*share.PriShare) ([]*share.PriShare,
	int) {
	anonymitySetSize := size
	if n >= size {
		anonymitySetSize = n
	}
	anonymitySet := make([]*share.PriShare, anonymitySetSize)
	copy(anonymitySet, shares)
	// When the number of shares is greater than the anonymity set (edge case),
	// the set of shares is the anonymity set
	if anonymitySetSize > n {
		for i := len(shares); i < anonymitySetSize; i++ {
			anonymitySet[i] = &share.PriShare{I: i, V: g.Scalar().Pick(rand)}
		}
	}
	return anonymitySet, anonymitySetSize
}
