package evaluation

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/files"
	"key_recovery/modules/secret"
	"key_recovery/modules/utils"
	"log"
	"strconv"

	crypto_protocols "key_recovery/modules/crypto"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// The goal is to have a granular measurement of the packet sizes
// It would be nice to have how much data is relevant,
// and how much data is simply random
// For this purpose, we use the tagged version of the functions
// which tell which shares and hashes are random
func EvaluateOverallPacketSize(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// First stores the size of the packets for varying size of privacy pool
	testCases, dirSubstr := GenerateTestCases(1, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Overall packet size",
		"Irrelevant information size",
		"Relevant information size",
		"Absolute Threshold",
		"Subsecrets",
		"Shares per packet",
	}
	data = append(data, topData)
	// totalSimulations := cfg.Iterations * cfg.Iterations
	totalSimulations := 1
	for _, tc := range testCases {
		sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSize(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSize(anonymityPacket,
						personNum, sharesInfo, hashesInfo)
				}
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
					sharesPerPacket,
				}
				data = append(data, row)
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}

	// Varying threshold
	data = nil
	data = append(data, topData)
	testCases, dirSubstr = GenerateTestCases(2, 1, false, cfg)
	csvDir = mainDir + dirSubstr
	err, _ = files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	for _, tc := range testCases {
		sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSize(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSize(anonymityPacket,
						personNum, sharesInfo, hashesInfo)
				}
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
					sharesPerPacket,
				}
				data = append(data, row)
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}

	// Varying trustees
	data = nil
	data = append(data, topData)
	testCases, dirSubstr = GenerateTestCases(3, 1, false, cfg)
	csvDir = mainDir + dirSubstr
	err, _ = files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	for _, tc := range testCases {
		sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSize(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSize(anonymityPacket,
						personNum, sharesInfo, hashesInfo)
				}
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
					sharesPerPacket,
				}
				data = append(data, row)
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.n) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}

	// Varying absolute threshold
	data = nil
	data = append(data, topData)
	testCases, dirSubstr = GenerateTestCases(4, 1, false, cfg)
	csvDir = mainDir + dirSubstr
	err, _ = files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	for _, tc := range testCases {
		sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSize(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSize(anonymityPacket,
						personNum, sharesInfo, hashesInfo)
				}
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
					sharesPerPacket,
				}
				data = append(data, row)
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.absoluteThreshold) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}

	// Varying subsecrets
	data = nil
	data = append(data, topData)
	testCases, dirSubstr = GenerateTestCases(6, 1, false, cfg)
	csvDir = mainDir + dirSubstr
	err, _ = files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	for _, tc := range testCases {
		sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSize(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSize(anonymityPacket,
						personNum, sharesInfo, hashesInfo)
				}
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
					sharesPerPacket,
				}
				data = append(data, row)
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.noOfSubsecrets) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}

	// Varying shares per person
	data = nil
	data = append(data, topData)
	testCases, dirSubstr = GenerateTestCases(5, 1, false, cfg)
	csvDir = mainDir + dirSubstr
	err, _ = files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	for _, tc := range testCases {
		sharesPerSS := utils.FloorDivide((100 * tc.absoluteThreshold), tc.percentageLeavesLayerThreshold)
		totalShares := sharesPerSS * tc.noOfSubsecrets
		sharesPerPacket := totalShares / tc.n
		if totalShares%tc.n != 0 {
			sharesPerPacket++
		}
		// sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSize(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSize(anonymityPacket,
						personNum, sharesInfo, hashesInfo)
				}
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
					sharesPerPacket,
				}
				data = append(data, row)
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(sharesPerPacket) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}
}

func EvaluateOnePacketSize(anonymityPacket secret.AdditivePacket) int {
	size := 0
	for _, shareData := range anonymityPacket.ShareData {
		shareBytes := crypto_protocols.ConvertShareToBytes(shareData)
		size += len(shareBytes)
	}

	for _, hash := range anonymityPacket.RelevantHashes {
		size += len(hash)
	}

	size += len(anonymityPacket.Salt)

	return size
}

func GetIrrelevantInfoSize(anonymityPacket secret.AdditivePacket, personNum int,
	sharesInfo, hashesInfo map[int][]int) int {
	irrelevantInfoSize := 0
	for _, hNum := range hashesInfo[personNum] {
		h := anonymityPacket.RelevantHashes[hNum]
		irrelevantInfoSize += len(h)
	}

	for _, sNum := range sharesInfo[personNum] {
		s := anonymityPacket.ShareData[sNum]
		sBytes := crypto_protocols.ConvertShareToBytes(s)
		irrelevantInfoSize += len(sBytes)
	}
	return irrelevantInfoSize
}

func EvaluateOverallPacketSize2(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// First stores the size of the packets for varying size of privacy pool
	testCases, dirSubstr := GenerateTestCases(1, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Overall packet size",
		"Irrelevant information size",
		"Relevant information size",
		"Absolute Threshold",
		"Subsecrets",
		"Shares per packet",
	}
	data = append(data, topData)
	// totalSimulations := cfg.Iterations * cfg.Iterations
	totalSimulations := 1
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			if tc.a != 50 {
				continue
			}
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				err = enc.Encode(anonymityPacket)
				if err != nil {
					fmt.Println("Error encoding struct:", err)
					return
				}

				// Get the byte slice from the buffer
				byteSlice := buf.Bytes()

				// Measure the size of the byte slice
				packetSize := len(byteSlice)

				irrelevantInfoSize := 0
				for _, h := range hashesInfo[personNum] {
					irrRelevantHash := anonymityPacket.RelevantHashes[h]
					var irrBuf bytes.Buffer
					irrEnc := gob.NewEncoder(&irrBuf)
					err = irrEnc.Encode(irrRelevantHash)
					if err != nil {
						fmt.Println("Error encoding struct:", err)
						return
					}

					// Get the byte slice from the buffer
					irrByteSlice := irrBuf.Bytes()

					// Measure the size of the byte slice
					irrSize := len(irrByteSlice)

					irrelevantInfoSize += irrSize
				}

				for _, s := range sharesInfo[personNum] {
					irrRelevantShare := anonymityPacket.ShareData[s]
					var irrBuf bytes.Buffer
					irrEnc := gob.NewEncoder(&irrBuf)
					err = irrEnc.Encode(irrRelevantShare)
					if err != nil {
						fmt.Println("Error encoding struct:", err)
						return
					}

					// Get the byte slice from the buffer
					irrByteSlice := irrBuf.Bytes()

					// Measure the size of the byte slice
					irrSize := len(irrByteSlice)

					irrelevantInfoSize += irrSize
				}

				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					packetSize,
					irrelevantInfoSize,
					packetSize - irrelevantInfoSize,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
				}
				data = append(data, row)

				for _, pkt := range anonymityPackets {
					for _, share := range pkt.ShareData {
						irrelevantShareVal := share.V
						// irrelevantShareInd := share.I
						var irrBuf bytes.Buffer
						irrEnc := gob.NewEncoder(&irrBuf)
						err = irrEnc.Encode(irrelevantShareVal)
						if err != nil {
							fmt.Println("Error encoding struct:", err)
							return
						}

						// Get the byte slice from the buffer
						irrByteSlice := irrBuf.Bytes()

						// Measure the size of the byte slice
						irrSize := len(irrByteSlice)
						var irrBuf2 bytes.Buffer
						irrelevantShare := share.I
						irrEnc2 := gob.NewEncoder(&irrBuf2)
						err = irrEnc2.Encode(irrelevantShare)
						if err != nil {
							fmt.Println("Error encoding struct:", err)
							return
						}

						// Get the byte slice from the buffer
						irrByteSlice2 := irrBuf2.Bytes()

						// Measure the size of the byte slice
						irrSize2 := len(irrByteSlice2)

						if irrSize2 != 6 {
							fmt.Println(share.I)
						}
						if irrSize2 == 6 {
							fmt.Println("---", share.I)
						}
						fmt.Println("Share size", irrSize, irrSize2)
					}
				}
			}
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + "-" + strconv.Itoa(tc.a) + ".csv"
		err, _ = files.CreateFile(csvFileName)
		if err != nil {
			log.Fatalln(err)
		}
		err = files.WriteToCSVFile(csvFileName, data)
		if err != nil {
			fmt.Println("Error in writing to the CSV file", err)
		}
	}
}
