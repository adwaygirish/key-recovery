package secret

import (
	"crypto/cipher"
	"log"
	"time"

	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/errors"
	"key_recovery/modules/utils"
	randm "math/rand"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func GetLargeSharePackets(
	g *edwards25519.SuiteEd25519,
	bitSecretString string,
	n int,
	randSeedShares cipher.Stream, absoluteThreshold int,
	noOfSubsecrets int,
	percentageLeavesLayerThreshold int,
) ([][]AdditivePacket, int, int, error) {

	byteSecretSlice := crypto_protocols.ConvertBitStringToBytes(bitSecretString)
	// If the percentage threshold is greater than 100, then it does not make
	// sense to run the recovery
	if percentageLeavesLayerThreshold > 100 {
		return nil, -1, -1, errors.ErrInvalidThreshold
	}

	var xUsedCoords []int
	var leavesDataSlice [][]*share.PriShare
	var subsecretsSlice [][]kyber.Scalar
	var parentSubsecretsSlice []map[*share.PriShare]kyber.Scalar
	for _, byteSecret := range byteSecretSlice {
		var leavesData []*share.PriShare
		var subsecrets []kyber.Scalar
		parentSubsecrets := make(map[*share.PriShare]kyber.Scalar)
		secretKey := g.Scalar().SetBytes(byteSecret)

		leavesNumbers := utils.GenerateAdditiveTwoLayeredTree(
			n, percentageLeavesLayerThreshold, absoluteThreshold, noOfSubsecrets)
		// Generate the shares for all the layers except the leaves layer
		GenerateAdditiveIndisUpperLayers(g, secretKey, randSeedShares,
			noOfSubsecrets, &subsecrets, &xUsedCoords)
		// Generate the shares for the leaves layer
		GenerateAdditiveIndisLeavesLayer(g, randSeedShares, absoluteThreshold,
			leavesNumbers, subsecrets, &leavesData, &xUsedCoords,
			parentSubsecrets)

		leavesDataSlice = append(leavesDataSlice, leavesData)
		subsecretsSlice = append(subsecretsSlice, subsecrets)
		parentSubsecretsSlice = append(parentSubsecretsSlice, parentSubsecrets)
	}

	var overallSharePacketsSlice, personwiseSharePacketsSlice [][]AdditivePacket
	var maxSharesPerPerson int
	for i := 0; i < len(leavesDataSlice); i++ {
		secretKey := g.Scalar().SetBytes(byteSecretSlice[i])
		sharePackets, msp, err := GetAdditiveSharePackets(g,
			randSeedShares, secretKey,
			n, absoluteThreshold,
			leavesDataSlice[i], subsecretsSlice[i],
			parentSubsecretsSlice[i],
			&xUsedCoords)
		if err == nil {
			log.Fatalln("share packets not generated properly")
		}
		maxSharesPerPerson = msp
		overallSharePacketsSlice = append(overallSharePacketsSlice, sharePackets)
	}

	for i := 0; i < n; i++ {
		var sharePacketsSlice []AdditivePacket
		for j := 0; j < len(leavesDataSlice); j++ {
			sharePacketsSlice = append(sharePacketsSlice,
				overallSharePacketsSlice[j][i])
		}
		personwiseSharePacketsSlice = append(personwiseSharePacketsSlice,
			sharePacketsSlice)
	}
	return personwiseSharePacketsSlice, maxSharesPerPerson,
		len(personwiseSharePacketsSlice[0]), nil
}

func GetLargeAnonymityPackets(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream, sharePackets [][]AdditivePacket,
	anonymitySetSize, maxSharesPerPerson, totalSecrets int,
	xUsedCoords *[]int) ([][]AdditivePacket, error) {
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	var anonymityPackets [][]AdditivePacket
	// First of all store all the secret share packets
	anonymityPackets = append(anonymityPackets, sharePackets...)
	// Then, store the random packets
	for i := 0; i < anonymitySetSize-len(sharePackets); i++ {
		var addPacketSlice []AdditivePacket
		for j := 0; j < totalSecrets; j++ {
			var addPacket AdditivePacket
			salt, _ := crypto_protocols.GenerateSalt32()
			addPacket.Salt = salt
			GenerateAdditiveRandomPackets(g, randSeedShares, rng,
				maxSharesPerPerson, &addPacket, xUsedCoords)
			randomBytes, err := crypto_protocols.GenerateRandomBytes(32)
			if err != nil {
				log.Fatalln("Error in generating random packets")
			}
			randomHash := crypto_protocols.GetSHA256(randomBytes)
			(addPacket).RelevantHashes = append((addPacket).RelevantHashes,
				randomHash)
		}
		anonymityPackets = append(anonymityPackets, addPacketSlice)
	}
	return anonymityPackets, nil
}

func LargeOptIndisSecretRecovery(g *edwards25519.SuiteEd25519,
	randSeedShares cipher.Stream,
	anonymityPackets [][]AdditivePacket, accessOrder []int,
	absoluteThreshold int) kyber.Scalar {
	anonymitySetSize := len(anonymityPackets)
	secretRecovered := false
	var usedShares []*share.PriShare
	var obtainedSubsecrets []kyber.Scalar
	var recoveredKey kyber.Scalar
	// For larger packets, we take the simplest approach first
	// We try to obtain the first subsecret of the first secret
	// Based on that, we mark the people as trustees and then, use
	// their shares for faster recovery
	for obtainedLength := 2; obtainedLength <= anonymitySetSize; obtainedLength++ {
		obtainedPacketsIndices := accessOrder[:obtainedLength]
		// fmt.Println(obtainedPacketsIndices)
		var peoplePackets []AdditivePacket
		for _, obtainedPacketIndex := range obtainedPacketsIndices {
			peoplePackets = append(peoplePackets,
				anonymityPackets[obtainedPacketIndex][0])
		}
		PersonwiseAdditiveOptIndisSecretRecovery(g, randSeedShares, peoplePackets,
			absoluteThreshold, &usedShares, &obtainedSubsecrets,
			&secretRecovered, &recoveredKey)
		if secretRecovered {
			break
		}
	}
	return recoveredKey
}
