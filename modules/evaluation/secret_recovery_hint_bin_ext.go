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
func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(1, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords,
				tc.noOfHints)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingThresholdBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(2, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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
}

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingATBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(1, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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
}

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingTrusteesBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(4, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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
}

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingSSBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(6, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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
}

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingHintsBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(7, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.noOfHints) + ".csv"
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryLargeAnonBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(7, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords,
				tc.noOfHints)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryExponentialBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(9, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	var f shamir.Field
	f.InitializeTables()
	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(28)
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
		"Hints",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateHintedTTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secretbe.GetHintedTSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords,
				tc.noOfHints)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetHintedTAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson,
				len(secretKey[0]), len(secretKey),
				&xUsedCoords, encryptionLength)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,

				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			recoveredSecretKey := shamir.AESKeyUint16sToKeyBytes(recoveredKey)
			if !crypto_protocols.CheckByteArrayEqual(secretKeyBytes, recoveredSecretKey) {
				log.Println(tc)
				log.Fatalln(err)
			}
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
				tc.noOfHints,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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
