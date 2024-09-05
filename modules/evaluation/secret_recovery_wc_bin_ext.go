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
func EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(1, 1, true, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords)

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

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
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
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(tc.a) + ".csv"
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

func EvaluateWCBasicHashedSecretRecoveryBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(1, 2, true, cfg)
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
	secretKeyHash := crypto_protocols.GetSHA256(shamir.Uint16sToBytes(secretKey))
	maxSize := 200
	var xUsedCoords []uint16

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			shareVals, err := secretbe.GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
				tc.n, secretKey, &xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			anonymityShareVals, _ := secretbe.GetDisAnonymitySet(f, tc.n, tc.a, maxSize, shareVals,
				&xUsedCoords, len(secretKey))
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()
			// _, err := secretbe.BasicHashedSecretRecovery(f,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err = secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonymityShareVals, accessOrder, secretKeyHash)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(tc.a) + ".csv"
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

// In this run of experiments, we evaluate the time taken based on the
// changing absolute threshold and changing number of subsecrets
func EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(2, 1, true, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords)

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
			// recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecovery(f,
			//
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
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
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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

func EvaluateWCBasicHashedSecretRecoveryVaryingThresholdBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(2, 2, true, cfg)
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
	secretKeyHash := crypto_protocols.GetSHA256(shamir.Uint16sToBytes(secretKey))
	maxSize := 200
	var xUsedCoords []uint16

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for tcIndex := len(testCases) - 1; tcIndex >= 0; tcIndex-- {
		tc := testCases[tcIndex]
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			shareVals, err := secretbe.GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
				tc.n, secretKey, &xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			anonymityShareVals, _ := secretbe.GetDisAnonymitySet(f, tc.n, tc.a, maxSize, shareVals,
				&xUsedCoords, len(secretKey))
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()
			// _, err := secretbe.BasicHashedSecretRecovery(f,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err = secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonymityShareVals, accessOrder, secretKeyHash)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
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

// In this run of experiments, we evaluate the time taken based on the
// changing number of trustees while keeping the percentage threshold
// constant with the
func EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(4, 1, true, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords)

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

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
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
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.n) + "-" + strconv.Itoa(tc.a) + ".csv"
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

func EvaluateWCBasicHashedSecretRecoveryVaryingTrusteesBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(4, 2, true, cfg)
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
	secretKeyHash := crypto_protocols.GetSHA256(shamir.Uint16sToBytes(secretKey))
	maxSize := 200
	var xUsedCoords []uint16

	var data [][]interface{}
	topData := []interface{}{
		"Trustees",
		"Anonymity Set Size",
		"Leaves Threshold",
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			shareVals, err := secretbe.GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
				tc.n, secretKey, &xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			anonymityShareVals, _ := secretbe.GetDisAnonymitySet(f, tc.n, tc.a, maxSize, shareVals,
				&xUsedCoords, len(secretKey))
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder_a := utils.GenerateOffsettedIndicesSet(tc.a-tc.n, tc.n)
			utils.Shuffle(accessOrder_a)
			accessOrder_n := utils.GenerateIndicesSet(tc.n)
			utils.Shuffle(accessOrder_n)
			var accessOrder []int
			accessOrder = append(accessOrder, accessOrder_a...)
			accessOrder = append(accessOrder, accessOrder_n...)

			startTime2 := time.Now()
			// _, err := secretbe.BasicHashedSecretRecovery(f,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err = secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonymityShareVals, accessOrder, secretKeyHash)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.n) + "-" + strconv.Itoa(tc.a) + ".csv"
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

// In this run of experiments, we evaluate the time taken based on the
// changing absolute threshold and changing number of subsecrets
func EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingATBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(3, 1, true, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations

	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords)

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

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
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
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.absoluteThreshold) + "-" + strconv.Itoa(tc.a) + ".csv"
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

func EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(6, 1, true, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords)

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

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
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
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.noOfSubsecrets) + "-" + strconv.Itoa(tc.a) + ".csv"
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

func EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryOptPerSSBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(5, 1, true, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Shares Per Trustee",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations
	for _, tc := range testCases {
		sharesPerSS := ((100 * tc.absoluteThreshold) / tc.percentageLeavesLayerThreshold)
		totalShares := sharesPerSS * tc.noOfSubsecrets
		sharesPerTrustee := totalShares / tc.n
		if totalShares%tc.n != 0 {
			sharesPerTrustee++
		}
		fmt.Println("Shares per trustee", sharesPerTrustee)
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
					secretKey, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
				secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
				sharePackets,
				tc.a, maxSharesPerPerson, len(secretKey),
				&xUsedCoords)

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

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
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
				sharesPerTrustee,
			}

			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(sharesPerTrustee) + "-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + "-" + strconv.Itoa(tc.a) + ".csv"
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
