package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/files"
	"key_recovery/modules/monitor"
	secretbe "key_recovery/modules/secret_binary_extension"
	"key_recovery/modules/shamir"
	"key_recovery/modules/utils"
	"log"
	"strconv"
)

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string,
	rangeIndicator int) {
	testCases, dirSubstr := GenerateTestCasesCPU(1, 1, rangeIndicator, false, cfg)
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
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
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

func EvaluateBasicHashedSecretRecoveryBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string,
	rangeIndicator int) {
	testCases, dirSubstr := GenerateTestCasesCPU(1, 2, rangeIndicator, false, cfg)
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
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage", tc.percentageLeavesLayerThreshold)
			totalTimer.Reset()
			shareVals, err := secretbe.GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
				tc.n, secretKey, &xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			anonPackets, _ := secretbe.GetDisAnonymitySet(f, tc.n, tc.a, maxSize, shareVals,
				&xUsedCoords, len(secretKey))
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			totalTimer.Reset()
			// _, err := secret.BasicHashedSecretRecovery(f,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonPackets, accessOrder, secretKeyHash)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			if err != nil {
				log.Fatalln(err)
			}
			if !crypto_protocols.CheckRecSecretKeyBinExt(secretKeyHash,
				recovered) {
				log.Println(tc)
				log.Fatalln("wrong recovery")
				continue
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(2, 1, false, cfg)
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
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()

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

func EvaluateBasicHashedSecretRecoveryVaryingThresholdBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(2, 2, false, cfg)
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
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for tcIndex := len(testCases) - 1; tcIndex >= 0; tcIndex-- {
		tc := testCases[tcIndex]
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage", tc.percentageLeavesLayerThreshold)
			totalTimer.Reset()
			shareVals, err := secretbe.GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
				tc.n, secretKey, &xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			anonPackets, _ := secretbe.GetDisAnonymitySet(f, tc.n, tc.a, maxSize, shareVals,
				&xUsedCoords, len(secretKey))
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			totalTimer.Reset()
			// _, err := secret.BasicHashedSecretRecovery(f,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonPackets, accessOrder, secretKeyHash)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			if err != nil {
				log.Fatalln(err)
			}
			if !crypto_protocols.CheckRecSecretKeyBinExt(secretKeyHash,
				recovered) {
				log.Println(tc)
				log.Fatalln("wrong recovery")
				continue
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(4, 1, false, cfg)
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
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	possibleSubsecrets := GetAllPossibleSubsecrets(2, cfg.DefaultPercentageThreshold,
		cfg.DefaultTrustees, cfg.DefaultAbsoluteThreshold)
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, subsecretNum := range possibleSubsecrets {
		for _, tc := range testCases {
			for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
				fmt.Println("Trustees:", tc.n)
				fmt.Println("Anonymity:", tc.a)
				fmt.Println("Absolute:", tc.absoluteThreshold)
				fmt.Println("Subsecrets:", subsecretNum)
				fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

				totalTimer.Reset()
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
				elapsedTime1 := totalTimer.Record()

				accessOrder := utils.GenerateIndicesSet(tc.a)
				utils.Shuffle(accessOrder)

				totalTimer.Reset()

				recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
					anonymityPackets, accessOrder,
					tc.absoluteThreshold)

				elapsedTime2 := totalTimer.Record()

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
					subsecretNum,
				}

				data = append(data, row)
				fmt.Println("Generation:", elapsedTime1)
				fmt.Println("Reconstruction:", elapsedTime2)
				fmt.Println("")
			}
			csvFileName := csvDir + "results-" + strconv.Itoa(subsecretNum) + "-" + strconv.Itoa(tc.a) + ".csv"
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
}

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoverySecretSizeBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(69, 1, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	// secretSizes := []int{2047, 4095, 8191, 16383, 32767, 65535}
	secretSizes := []int{15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535}
	var f shamir.Field
	f.InitializeTables()

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
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for _, skSize := range secretSizes {
			secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(skSize)
			if err != nil {
				log.Fatalln(err)
			}
			secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)
			for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
				fmt.Println("Trustees:", tc.n)
				fmt.Println("Anonymity:", tc.a)
				fmt.Println("Absolute:", tc.absoluteThreshold)
				fmt.Println("Subsecrets:", tc.noOfSubsecrets)
				fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

				totalTimer.Reset()
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
				elapsedTime1 := totalTimer.Record()

				accessOrder := utils.GenerateIndicesSet(tc.a)
				utils.Shuffle(accessOrder)
				// fmt.Println(accessOrder)

				totalTimer.Reset()

				recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
					anonymityPackets, accessOrder,
					tc.absoluteThreshold)

				elapsedTime2 := totalTimer.Record()
				row := []interface{}{
					tc.n,
					tc.a,
					tc.percentageLeavesLayerThreshold,
					elapsedTime1,
					elapsedTime2,
					tc.absoluteThreshold,
					tc.noOfSubsecrets,
				}

				if !crypto_protocols.CompareUint16s(secretKey,
					recoveredKey) {
					log.Println(tc)
					log.Fatalln(err)
					continue
				}
				data = append(data, row)
				fmt.Println("Generation:", elapsedTime1)
				fmt.Println("Reconstruction:", elapsedTime2)
				fmt.Println("")
			}
			csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(skSize) + ".csv"
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
}

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT4BinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 4
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT5BinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 5
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT6BinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 6
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				tc.a,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}

			if !crypto_protocols.CompareUint16s(secretKey,
				recoveredKey) {
				log.Println(tc)
				log.Fatalln(err)
				continue
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string,
	rangeIndicator int) {
	testCases, dirSubstr := GenerateTestCasesHintedTCPU(1, 1, rangeIndicator, false, cfg)
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
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Hints:", tc.noOfHints)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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
			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.HintedTOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()

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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExtCPU(
	cfg *configuration.SimulationConfig,
	mainDir string,
	rangeIndicator int) {
	testCases, dirSubstr := GenerateTestCasesThresholdedCPU(1, 1, rangeIndicator, false, cfg)
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
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
	totalTimer := monitor.NewMonitor()
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Absolute:", tc.absoluteThreshold)
			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
			fmt.Println("Subsecrets Threshold:", tc.percentageSubsecretsThreshold)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			totalTimer.Reset()
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

			elapsedTime1 := totalTimer.Record()

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			totalTimer.Reset()

			recoveredKey := secretbe.ThOptUsedIndisSecretRecoveryParallelized(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := totalTimer.Record()

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
