package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/files"
	secret "key_recovery/modules/secret_binary_extension"
	"key_recovery/modules/shamir"
	"log"
	"strconv"

	crypto_protocols "key_recovery/modules/crypto"
)

// The goal is to have a granular measurement of the packet sizes
// It would be nice to have how much data is relevant,
// and how much data is simply random
// For this purpose, we use the tagged version of the functions
// which tell which shares and hashes are random
func EvaluateOverallPacketSizeBinExt(
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
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
	if err != nil {
		log.Fatalln(err)
	}
	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

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
		for simulationNumber := 0; simulationNumber < totalSimulations*100; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(
				f, secretKey, len(secretKey), tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSizeBinExt(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSizeBinExt(anonymityPacket,
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

	testCases, dirSubstr = GenerateTestCases(2, 1, false, cfg)
	csvDir = mainDir + dirSubstr
	err, _ = files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	data = make([][]interface{}, 0)
	data = append(data, topData)
	// totalSimulations := cfg.Iterations * cfg.Iterations
	totalSimulations = 1
	for _, tc := range testCases {
		sharesPerPacket := 2
		for simulationNumber := 0; simulationNumber < totalSimulations*100; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(
				f, secretKey, len(secretKey), tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSizeBinExt(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSizeBinExt(anonymityPacket,
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
		csvFileName := csvDir + "results-th-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + ".csv"
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

func EvaluateOverallBaselinePacketSizeBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string,
) {
	// First stores the size of the packets for varying size of privacy pool
	testCases, dirSubstr := GenerateTestCases(1, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
	if err != nil {
		log.Fatalln(err)
	}
	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

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
		for simulationNumber := 0; simulationNumber < totalSimulations*100; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secret.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, trusteesSharesInfo,
				trusteesHashesInfo, err := secret.GetAdditiveSharePacketsTagged(
				f, secretKey, len(secretKey), tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, sharesInfo, hashesInfo,
				err := secret.GetAdditiveAnonymityPacketsTagged(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords, trusteesSharesInfo, trusteesHashesInfo)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			for personNum, anonymityPacket := range anonymityPackets {

				// Measure the size of the byte slice
				packetSize := EvaluateOnePacketSizeBinExt(anonymityPacket)

				irrelevantInfoSize := 0
				if len(sharesInfo[personNum]) == len(anonymityPacket.ShareData) {
					irrelevantInfoSize = packetSize
				} else {
					irrelevantInfoSize = GetIrrelevantInfoSizeBinExt(anonymityPacket,
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
}

func EvaluateOnePacketSizeBinExt(anonymityPacket secret.AdditivePacket) int {
	size := 0
	for _, shareData := range anonymityPacket.ShareData {
		yBytes := shamir.Uint16sToBytes(shareData.Y)
		lenXBytes := 2
		size += len(yBytes)
		size += lenXBytes
	}

	for _, hash := range anonymityPacket.RelevantHashes {
		size += len(hash)
	}

	size += len(anonymityPacket.Salt)

	return size
}

func GetIrrelevantInfoSizeBinExt(anonymityPacket secret.AdditivePacket, personNum int,
	sharesInfo, hashesInfo map[int][]int) int {
	irrelevantInfoSize := 0
	for _, hNum := range hashesInfo[personNum] {
		h := anonymityPacket.RelevantHashes[hNum]
		irrelevantInfoSize += len(h)
	}

	for _, sNum := range sharesInfo[personNum] {
		shareData := anonymityPacket.ShareData[sNum]
		yBytes := shamir.Uint16sToBytes(shareData.Y)
		lenXBytes := 2
		irrelevantInfoSize += len(yBytes)
		irrelevantInfoSize += lenXBytes
	}
	return irrelevantInfoSize
}
