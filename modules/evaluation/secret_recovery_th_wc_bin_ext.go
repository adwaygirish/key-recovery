package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/files"
	secretbe "key_recovery/modules/secret_binary_extension"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
	"log"
	"strconv"
	"time"
)

// This is the worst case evaluation of the secret recovery
// It is the worst case because the user approaches all the people
// with the random blobs first, and then, approaches the people with the
// shares
func EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(1, 1, true, cfg)
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
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKeyBytes)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Subsecrets Threshold:", tc.percentageSubsecretsThreshold)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secretbe.GetThresholdedAnonymityPackets(
				sharePackets, tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()

			// recoveredKey := secretbe.ThOptUsedIndisSecretRecovery(g,
			//
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secretbe.ThOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.percentageSubsecretsThreshold,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(tc.percentageSubsecretsThreshold) + ".csv"
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

func EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThresholdBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(2, 1, true, cfg)
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
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKeyBytes)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Subsecrets Threshold:", tc.percentageSubsecretsThreshold)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secretbe.GetThresholdedAnonymityPackets(
				sharePackets, tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()

			// recoveredKey := secretbe.ThOptUsedIndisSecretRecovery(g,
			//
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secretbe.ThOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.percentageSubsecretsThreshold,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + "-" + strconv.Itoa(tc.percentageSubsecretsThreshold) + ".csv"
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

func EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingATBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(3, 1, true, cfg)
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
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKeyBytes)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Subsecrets Threshold:", tc.percentageSubsecretsThreshold)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secretbe.GetThresholdedAnonymityPackets(
				sharePackets, tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()

			// recoveredKey := secretbe.ThOptUsedIndisSecretRecovery(g,
			//
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secretbe.ThOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.percentageSubsecretsThreshold,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.absoluteThreshold) + "-" + strconv.Itoa(tc.percentageSubsecretsThreshold) + ".csv"
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

func EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrusteesBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(4, 1, true, cfg)
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
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKeyBytes)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Subsecrets Threshold:", tc.percentageSubsecretsThreshold)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secretbe.GetThresholdedAnonymityPackets(
				sharePackets, tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()

			recoveredKey := secretbe.ThOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.percentageSubsecretsThreshold,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.n) + "-" + strconv.Itoa(tc.percentageSubsecretsThreshold) + ".csv"
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

func EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSSBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(6, 1, true, cfg)
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
	secretKey := shamir.KeyBytesToAESKeyUint16s(secretKeyBytes)

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Subsecrets Threshold:", tc.percentageSubsecretsThreshold)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateThresholdedTwoLayeredOptIndisShares(f, tc.n, secretKey,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetThresholdedSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secretbe.GetThresholdedAnonymityPackets(
				sharePackets, tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()

			// recoveredKey := secretbe.ThOptUsedIndisSecretRecovery(g,
			//
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secretbe.ThOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.percentageSubsecretsThreshold,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.noOfSubsecrets) + "-" + strconv.Itoa(tc.percentageSubsecretsThreshold) + ".csv"
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
