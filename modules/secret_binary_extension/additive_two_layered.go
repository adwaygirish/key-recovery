package secret_binary_extension

import (
	"log"

	"crypto/rand"
	"encoding/binary"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
)

type AdditivePacket struct {
	Salt           [32]byte          // includes the list of salts used for each share
	RelevantHashes [][32]byte        // includes the list of h(salt || parent secret)
	ShareData      []shamir.PriShare // share data (for now only one share)
}

var routinesMap = map[int]int{
	20:  2,
	40:  4,
	100: 8,
	400: 16,
}

// This function simply provides the shares
// It provides shares at random x-coordinates
// Generating shares by using this method ensures that all the
// shares are at different points and thus, an adversary cannot get any
// information about which layer the secret is from
func GenerateRandomXShares(f shamir.Field, t int, n int, secretKey []uint16,
	xUsedCoords *[]uint16) ([]shamir.PriShare, error) {
	shareVals, _, err := f.SplitUniqueX(secretKey, n, t, xUsedCoords)
	if err != nil {
		log.Fatalln(err)
	}
	return shareVals, nil
}

// This function is for additive secret sharing in the subsecrets layer
// This makes our life simpler and also makes the explanation of our code
// way simpler
// Hence, for this design, we do not need the percentage of threshold in the
// the subsecrets level
func GenerateAdditiveTwoLayeredOptIndisShares(f shamir.Field, n int,
	secretKey []uint16, absoluteThreshold int,
	noOfSubsecrets int,
	percentageLeavesLayerThreshold int) ([][]uint16, []shamir.PriShare,
	map[uint16][]uint16, []uint16, error) {
	f.InitializeTables()
	// Shares which are to be distributed among the trustees
	leavesData := make([]shamir.PriShare, 0)
	var xUsedCoords []uint16
	var subsecrets [][]uint16
	parentSubsecrets := make(map[uint16][]uint16)

	// If the percentage threshold is greater than 100, then it does not make
	// sense to run the recovery
	if percentageLeavesLayerThreshold > 100 {
		return nil, nil, nil, nil, errors.ErrInvalidThreshold
	}

	leavesNumbers := utils.GenerateAdditiveTwoLayeredTree(
		n, percentageLeavesLayerThreshold, absoluteThreshold, noOfSubsecrets)
	// Generate the shares for all the layers except the leaves layer
	GenerateAdditiveIndisUpperLayers(f, secretKey,
		noOfSubsecrets, &subsecrets)
	// Generate the shares for the leaves layer
	GenerateAdditiveIndisLeavesLayer(f, absoluteThreshold,
		leavesNumbers, subsecrets, &leavesData, &xUsedCoords,
		parentSubsecrets)

	return subsecrets, leavesData, parentSubsecrets, xUsedCoords, nil
}

// This function is called by the GenerateAdditiveTwoLayeredOptIndisShares
// for generating shares of the layers above the leaves
// Simply generates (n-1) random points and then, generates the point which is
// secret key minus the sum of the (n-1) points
func GenerateAdditiveIndisUpperLayers(f shamir.Field, secretKey []uint16,
	noOfSubsecrets int, subsecrets *[][]uint16) {
	buf := make([]byte, 2)
	sharesSums := make([]uint16, len(secretKey))
	// The first (n - 1) shares are generated randomly
	for i := 0; i < noOfSubsecrets-1; i++ {
		(*subsecrets) = append((*subsecrets), []uint16{})
		for j := 0; j < len(secretKey); j++ {
			if _, err := rand.Read(buf); err != nil {
				log.Fatalln(err)
			}
			shareVal := binary.BigEndian.Uint16(buf)
			(*subsecrets)[i] = append((*subsecrets)[i], shareVal)
			sharesSums[j] = shamir.Add(sharesSums[j], shareVal)
		}
	}
	// The last share is the XOR of rest of the shares with the
	// secret key
	(*subsecrets) = append((*subsecrets), []uint16{})
	for j := 0; j < len(secretKey); j++ {
		lastShare := shamir.Add(sharesSums[j], secretKey[j])
		(*subsecrets)[noOfSubsecrets-1] = append((*subsecrets)[noOfSubsecrets-1],
			lastShare)
	}
}

// This function is called by the GenerateAdditiveTwoLayeredOptIndisShares
// for generating the leaves layer
func GenerateAdditiveIndisLeavesLayer(f shamir.Field,
	absoluteThreshold int,
	leavesNumbers []int, subsecrets [][]uint16,
	leavesData *[]shamir.PriShare, xUsedCoords *[]uint16,
	parentSubsecrets map[uint16][]uint16) {
	for subsecretIndex, sharesNumber := range leavesNumbers {
		subsecretVal := subsecrets[subsecretIndex]
		shareVals, err := GenerateRandomXShares(f, absoluteThreshold,
			sharesNumber, subsecretVal, xUsedCoords)
		if err != nil {
			log.Fatalln(err)
		}
		*leavesData = append(*leavesData, shareVals...)
		for _, shareVal := range shareVals {
			parentSubsecrets[shareVal.X] = subsecretVal
		}
	}
}

// The packet generation does not require any x-coordinates
// Therefore, there is no need to store any kind of marker info
// Storing only two salted hash works for our system
func GetAdditiveSharePackets(f shamir.Field, secretKey []uint16,
	trustees, absoluteThreshold int,
	leavesData []shamir.PriShare, subsecrets [][]uint16,
	parentSubsecrets map[uint16][]uint16,
	xUsedCoords *[]uint16) ([]AdditivePacket, int, error) {
	if absoluteThreshold > trustees {
		return nil, -1, errors.ErrInvalidThreshold
	}
	var anonymitySharePackets []AdditivePacket
	totalShares := len(leavesData)
	sharesPerPerson := totalShares / trustees
	// Get how many shares each person should get
	personWiseShareDistribution, maxSharesPerPerson :=
		utils.GetPersonWiseShareNumber(trustees,
			totalShares, sharesPerPerson)
	// Indices of the leaves
	leavesIndices := utils.GenerateIndicesSet(totalShares)
	// Randomize the leaves that the trustees should receive
	utils.Shuffle(leavesIndices)
	currentIndex := 0
	for i := 0; i < trustees; i++ {
		var addPacket AdditivePacket
		noOfSharesReceived := personWiseShareDistribution[i]
		salt, _ := crypto_protocols.GenerateSalt32()
		addPacket.Salt = salt
		// Add the shares and the corresponding hashes
		GenerateAdditivePerPersonSharePackets(noOfSharesReceived, leavesIndices,
			leavesData, &currentIndex, secretKey, parentSubsecrets, &addPacket)
		// Get the size of the slice needed for representing the secret
		relevantSize := len(addPacket.ShareData[0].Y)
		// If the person has less than the maximum number of shares assigned to
		// in the set of trustees, then add some
		if noOfSharesReceived < maxSharesPerPerson {
			noOfPackets := maxSharesPerPerson - noOfSharesReceived
			GenerateAdditiveRandomPackets(noOfPackets, relevantSize,
				&addPacket, xUsedCoords)
		}
		anonymitySharePackets = append(anonymitySharePackets, addPacket)
	}
	return anonymitySharePackets, maxSharesPerPerson, nil
}

func GenerateAdditivePerPersonSharePackets(noOfSharesReceived int,
	leavesIndices []int, leavesData []shamir.PriShare, currentIndex *int,
	secretKey []uint16, parentSubsecrets map[uint16][]uint16,
	addPacket *AdditivePacket) {
	// Convert the secret key to bytes for getting the hash
	secretKeyBytes := shamir.Uint16sToBytes(secretKey)
	// Get the salted hash of the secret key
	secretHash := crypto_protocols.GetSaltedHash((*addPacket).Salt, secretKeyBytes)
	(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes, secretHash)
	for j := 0; j < noOfSharesReceived; j++ {
		leafShareVal := leavesData[leavesIndices[*currentIndex]]
		parentSubsecret := parentSubsecrets[leafShareVal.X]
		parentSubsecretBytes := shamir.Uint16sToBytes(parentSubsecret)
		subsecretHash := crypto_protocols.GetSaltedHash((*addPacket).Salt,
			parentSubsecretBytes)
		// If the share of the same subsecrets are being stored
		// then do not store the hash twice
		// To keep the packets indistinguishable, store some random blobs
		// inside the packets
		if !crypto_protocols.GetHashMembership((*addPacket).RelevantHashes, subsecretHash) {
			(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes, subsecretHash)
		} else {
			randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			randomHash := crypto_protocols.GetSHA256(randomBytes)
			(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes,
				randomHash)
		}
		(*addPacket).ShareData = append((*addPacket).ShareData, leafShareVal)
		(*currentIndex)++
	}
}

func GenerateAdditiveRandomPackets(noOfPackets, relevantSize int,
	addPacket *AdditivePacket, xUsedCoords *[]uint16) {
	bufX := make([]byte, 2)
	// This is for getting random Y's
	bufY := make([]byte, 2*relevantSize)
	for j := 0; j < (noOfPackets); {
		if _, err := rand.Read(bufX); err != nil {
			log.Fatalln(err)
		}
		x := binary.BigEndian.Uint16(bufX)
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
		if _, err := rand.Read(bufY); err != nil {
			log.Fatalln(err)
		}
		y := shamir.BytesToUint16s(bufY)
		(*xUsedCoords) = append((*xUsedCoords), x)
		randShareVal := shamir.PriShare{X: x, Y: y}
		(*addPacket).ShareData = append((*addPacket).ShareData, randShareVal)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		randomHash := crypto_protocols.GetSHA256(randomBytes)
		(*addPacket).RelevantHashes = append((*addPacket).RelevantHashes,
			randomHash)
		j++
	}
}

func GetAdditiveAnonymityPackets(sharePackets []AdditivePacket,
	anonymitySetSize, maxSharesPerPerson, relevantSize int,
	xUsedCoords *[]uint16) ([]AdditivePacket, error) {
	var anonymityPackets []AdditivePacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then. store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var addPacket AdditivePacket
		salt, _ := crypto_protocols.GenerateSalt32()
		addPacket.Salt = salt
		GenerateAdditiveRandomPackets(
			maxSharesPerPerson, relevantSize, &addPacket, xUsedCoords)
		randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalln("Error in generating random packets")
		}
		randomHash := crypto_protocols.GetSHA256(randomBytes)
		(addPacket).RelevantHashes = append((addPacket).RelevantHashes,
			randomHash)
		anonymityPackets = append(anonymityPackets, addPacket)
	}
	return anonymityPackets, nil
}
