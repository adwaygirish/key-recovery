package secret

import (
	"crypto/cipher"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/utils"

	"key_recovery/modules/errors"
	"log"
	randm "math/rand"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

var recoveryHint = 100000

type HintedTPacket struct {
	Nonce               [32]byte          // includes the list of salts used for each share
	RelevantEncryptions [][]byte          // includes the list of h(salt || parent secret)
	ShareData           []*share.PriShare // share data (for now only one share)
}

// The packet generation does not require any x-coordinates
// Therefore, there is no need to store any kind of marker info
// Storing only two salted hash works for our system
func GetHintedTSharePackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, secretKey kyber.Scalar,
	trustees, absoluteThreshold int,
	leavesData []*share.PriShare, subsecrets []kyber.Scalar,
	parentSubsecrets map[*share.PriShare]kyber.Scalar,
	xUsedCoords *[]int, noOfHints int) ([]HintedTPacket, int, int, error) {
	if absoluteThreshold > trustees {
		return nil, -1, -1, errors.ErrInvalidThreshold
	}
	var encryptionLength int
	var anonymitySharePackets []HintedTPacket
	// Randomness will be used for setting the x-coordinate of the share
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	totalShares := len(leavesData)
	sharesPerPerson := totalShares / trustees
	// Get how many shares each person should get
	personWiseShareDistribution, maxSharesPerPerson :=
		utils.GetPersonWiseShareNumber(trustees,
			totalShares, sharesPerPerson)
	trusteesNums := utils.GenerateIndicesSet(trustees)
	utils.Shuffle(trusteesNums)
	hintedTrustees := trusteesNums[:noOfHints][:]
	trusteesWiseHints := make(map[int]int)
	for i := 0; i < trustees; i++ {
		if hintedTrustees[i%len(hintedTrustees)] != i {
			trusteesWiseHints[i] = hintedTrustees[i%len(hintedTrustees)]
		} else {
			trusteesWiseHints[i] = hintedTrustees[(i+1)%len(hintedTrustees)]
		}
	}
	// Indices of the leaves
	leavesIndices := utils.GenerateIndicesSet(totalShares)
	// Randomize the leaves that the trustees should receive
	utils.Shuffle(leavesIndices)
	currentIndex := 0
	for i := 0; i < trustees; i++ {
		var hPacket HintedTPacket
		noOfSharesReceived := personWiseShareDistribution[i]
		nonce, _ := crypto_protocols.GenerateSalt32()
		hPacket.Nonce = nonce
		el, err := GenerateHintedTPerPersonSharePackets(noOfSharesReceived, leavesIndices,
			leavesData, &currentIndex, secretKey, parentSubsecrets, &hPacket,
			trusteesWiseHints[i])
		if err != nil {
			return nil, -1, -1, err
		}
		encryptionLength = el
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateHintedTRandomPackets(g, randSeedShares, rng, noOfPackets,
				&hPacket, xUsedCoords, encryptionLength)
		}
		anonymitySharePackets = append(anonymitySharePackets, hPacket)
	}
	return anonymitySharePackets, maxSharesPerPerson, encryptionLength, nil
}

func GenerateHintedTPerPersonSharePackets(noOfSharesReceived int,
	leavesIndices []int, leavesData []*share.PriShare, currentIndex *int,
	secretKey kyber.Scalar, parentSubsecrets map[*share.PriShare]kyber.Scalar,
	hPacket *HintedTPacket, hint int) (int, error) {
	var encryptionLength int
	noncedEncSecretKey, encryptionLength, err := crypto_protocols.GetHintedRelevantEncryption((*hPacket).Nonce, secretKey, recoveryHint)
	if err != nil {
		return -1, err
	}
	(*hPacket).RelevantEncryptions = append((*hPacket).RelevantEncryptions,
		noncedEncSecretKey)
	for j := 0; j < noOfSharesReceived; j++ {
		leafShareVal := leavesData[leavesIndices[*currentIndex]]
		parentSubsecret := parentSubsecrets[leafShareVal]
		noncedEncryption, _, err := crypto_protocols.GetHintedRelevantEncryption((*hPacket).Nonce, parentSubsecret, hint)
		if err != nil {
			log.Fatal(err)
			return -1, err
		}
		// If the share of the same subsecrets are being stored
		// then do not store the hash twice
		// To keep the packets indistinguishable, store some random blobs
		// inside the packets
		if !crypto_protocols.GetEncryptionMembership((*hPacket).RelevantEncryptions, noncedEncryption) {
			(*hPacket).RelevantEncryptions = append((*hPacket).RelevantEncryptions, noncedEncryption)
		} else {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			(*hPacket).RelevantEncryptions = append((*hPacket).RelevantEncryptions,
				randomBytes)
		}
		(*hPacket).ShareData = append((*hPacket).ShareData, leafShareVal)
		(*currentIndex)++
	}
	return encryptionLength, nil
}

func GenerateHintedTRandomPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, rng *randm.Rand, noOfPackets int,
	hPacket *HintedTPacket, xUsedCoords *[]int, encryptionLength int) {
	allXCoords := utils.GenerateIndicesSet(xSpace)
	for j := 0; j < (noOfPackets); j++ {
		relevantXCoords := utils.FindDifference(allXCoords, *xUsedCoords)
		indexXCoord := rng.Intn(len(relevantXCoords))
		xCoord := relevantXCoords[indexXCoord]
		(*xUsedCoords) = append((*xUsedCoords), xCoord)
		randShareVal := &share.PriShare{xCoord,
			g.Scalar().Pick(randSeedShares)}
		(*hPacket).ShareData = append((*hPacket).ShareData, randShareVal)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		(*hPacket).RelevantEncryptions = append((*hPacket).RelevantEncryptions,
			randomBytes)
	}
}

func GetHintedTAnonymityPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, sharePackets []HintedTPacket,
	anonymitySetSize int, maxSharesPerPerson int,
	xUsedCoords *[]int, encryptionLength int) ([]HintedTPacket, error) {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	var anonymityPackets []HintedTPacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var hPacket HintedTPacket
		nonce, _ := crypto_protocols.GenerateSalt32()
		hPacket.Nonce = nonce
		GenerateHintedTRandomPackets(g, randSeedShares, rng,
			maxSharesPerPerson, &hPacket, xUsedCoords, encryptionLength)
		// Store an encryption that would be similar to the encryption of the
		// secret key
		// This is to ensure that the number of encryptions remains the same
		// in share packets and anonymity packets
		randomBytes, err := crypto_protocols.GenerateRandomBytes(encryptionLength)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		(hPacket).RelevantEncryptions = append((hPacket).RelevantEncryptions,
			randomBytes)
		anonymityPackets = append(anonymityPackets, hPacket)
	}
	return anonymityPackets, nil
}
