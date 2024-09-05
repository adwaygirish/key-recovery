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
	"time"
)

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 1000
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
	for obtainedNumber := 1; obtainedNumber <= tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			startTime2 := time.Now()

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(
	cfg *configuration.SimulationConfig,
	mainDir string,
	lower int,
	upper int) {
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = upper
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
	for obtainedNumber := lower; obtainedNumber <= tc.a; obtainedNumber++ {
		if lower > 400 && lower <= 600 {
			totalSimulations = 5
		} else {
			if lower > 600 {
				totalSimulations = 3
			}
		}
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			startTime2 := time.Now()

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 1000
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
	totalTimer := monitor.NewMonitor()
	for obtainedNumber := 1; obtainedNumber <= tc.a; obtainedNumber++ {
		// if obtainedNumber <= 30 {
		// 	totalSimulations = 10
		// } else {
		// 	if obtainedNumber <= 50 {
		// 		totalSimulations = 5
		// 	} else {
		// 		totalSimulations = 2
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-cpu-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(
	cfg *configuration.SimulationConfig,
	mainDir string,
	lower int,
	upper int) {
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = upper
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
	totalTimer := monitor.NewMonitor()
	for obtainedNumber := lower; obtainedNumber <= upper; obtainedNumber++ {
		if lower > 400 && lower <= 600 {
			totalSimulations = 5
		} else {
			if lower > 600 {
				totalSimulations = 3
			}
		}
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-cpu-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson4(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 4
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			startTime2 := time.Now()

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-4-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson4CPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 4
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	totalTimer := monitor.NewMonitor()
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-4-cpu-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson5(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 5
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			startTime2 := time.Now()

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-4-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson5CPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 5
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	totalTimer := monitor.NewMonitor()
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-4-cpu-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson6(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 6
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)
			// fmt.Println(accessOrder)

			startTime2 := time.Now()

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-4-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson6CPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	cfg.DefaultAbsoluteThreshold = 6
	testCases, dirSubstr := GenerateTestCases(100, 1, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	totalTimer := monitor.NewMonitor()
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		// if obtainedNumber <= 50 {
		// 	totalSimulations = 50
		// } else {
		// 	if obtainedNumber <= 100 {
		// 		totalSimulations = 20
		// 	} else {
		// 		totalSimulations = 10
		// 	}
		// }
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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

			secretbe.AdditiveOptUsedIndisSecretRecoveryParallelizedPerPerson(f,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold, obtainedNumber)

			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				obtainedNumber,
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
		csvFileName := csvDir + "results-4-cpu-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateBasicHashedSecretRecoveryBinExtPerPerson(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(100, 2, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	maxSize := 600

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
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		if obtainedNumber <= 20 {
			totalSimulations = 10
		} else {
			if obtainedNumber <= 26 {
				totalSimulations = 5
			} else {
				totalSimulations = 2
			}
		}
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			var xUsedCoords []uint16
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
			fmt.Println("Percentage", tc.percentageLeavesLayerThreshold)
			startTime1 := time.Now()
			shareVals, err := secretbe.GenerateSharesPercentage(f, tc.percentageLeavesLayerThreshold,
				tc.n, secretKey, &xUsedCoords)
			if err != nil {
				log.Fatalln(err)
			}
			anonPackets, _ := secretbe.GetDisAnonymitySet(f, tc.n, tc.a, maxSize, shareVals,
				&xUsedCoords, len(secretKey))
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()
			// _, err := secret.BasicHashedSecretRecovery(f,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			secretbe.BasicHashedSecretRecoveryParallelizedPerPersonUint16(f,
				anonPackets, accessOrder, secretKeyHash, obtainedNumber)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
			row := []interface{}{
				tc.n,
				obtainedNumber,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			if err != nil {
				log.Fatalln(err)
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-" + strconv.Itoa(obtainedNumber) + ".csv"
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

func EvaluateBasicHashedSecretRecoveryBinExtPerPersonCPU(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(100, 2, false, cfg)
	tc := testCases[0]
	tc.a = 500
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
	maxSize := 600

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
	totalTimer := monitor.NewMonitor()
	for obtainedNumber := 2; obtainedNumber < tc.a; obtainedNumber++ {
		if obtainedNumber <= 20 {
			totalSimulations = 10
		} else {
			if obtainedNumber <= 26 {
				totalSimulations = 5
			} else {
				totalSimulations = 2
			}
		}
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			var xUsedCoords []uint16
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", obtainedNumber)
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
			secretbe.BasicHashedSecretRecoveryParallelizedPerPersonUint16(f,
				anonPackets, accessOrder, secretKeyHash, obtainedNumber)
			if err != nil {
				log.Fatalln(err)
				continue
			}
			elapsedTime2 := totalTimer.Record()
			row := []interface{}{
				tc.n,
				obtainedNumber,
				tc.percentageLeavesLayerThreshold,
				elapsedTime1,
				elapsedTime2,
				tc.absoluteThreshold,
				tc.noOfSubsecrets,
			}
			if err != nil {
				log.Fatalln(err)
			}
			data = append(data, row)
			fmt.Println("Generation:", elapsedTime1)
			fmt.Println("Reconstruction:", elapsedTime2)
			fmt.Println("")
		}
		csvFileName := csvDir + "results-cpu-" + strconv.Itoa(obtainedNumber) + ".csv"
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

// // In this run of experiments, we evaluate the time taken based on the
// // changing absolute threshold and changing number of subsecrets
// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(2, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 			}
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 			}
// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// // In this run of experiments, we evaluate the time taken based on the
// // changing number of trustees while keeping the percentage threshold
// // constant with the
// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(4, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)
// 			// utils.Shuffle(accessOrder)
// 			// fmt.Println(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 			}
// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(tc.n) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// // In this run of experiments, we evaluate the time taken based on the
// // changing absolute threshold and changing number of subsecrets
// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingATBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(3, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	// Since the cases with absolute threshold as greater than 4 is quite slow
// 	// we run the experiments first with absolute threshold 3 and 4
// 	for _, tc := range testCases {
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)
// 			// utils.Shuffle(accessOrder)
// 			// fmt.Println(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 			}
// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(tc.absoluteThreshold) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(6, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 			}
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 			}

// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(tc.noOfSubsecrets) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSharesPerPersonBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(5, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 		"Shares Per Trustee",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		sharesPerSS := utils.FloorDivide((100 * tc.absoluteThreshold), tc.percentageLeavesLayerThreshold)
// 		totalShares := sharesPerSS * tc.noOfSubsecrets
// 		sharesPerTrustee := totalShares / tc.n
// 		if totalShares%tc.n != 0 {
// 			sharesPerTrustee++
// 		}
// 		fmt.Println("Shares per trustee", sharesPerTrustee)
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 			}
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 				sharesPerTrustee,
// 			}

// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(sharesPerTrustee) + "-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryLargeAnonBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(7, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)
// 			// fmt.Println(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 			}

// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryExponentialBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string,
// ) {
// 	testCases, dirSubstr := GenerateTestCases(8, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}
// 	var f shamir.Field
// 	f.InitializeTables()
// 	secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(31)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 			fmt.Println("Trustees:", tc.n)
// 			fmt.Println("Anonymity:", obtainedNumber)
// 			fmt.Println("Absolute:", tc.absoluteThreshold)
// 			fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 			startTime1 := time.Now()
// 			subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 				secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 					secretKey, tc.absoluteThreshold,
// 					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}

// 			sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 				secretKey, tc.n, tc.absoluteThreshold,
// 				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 				sharePackets,
// 				tc.a, maxSharesPerPerson, len(secretKey),
// 				&xUsedCoords)

// 			if err != nil {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 			accessOrder := utils.GenerateIndicesSet(tc.a)
// 			utils.Shuffle(accessOrder)
// 			// fmt.Println(accessOrder)

// 			startTime2 := time.Now()

// 			recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 				anonymityPackets, accessOrder,
// 				tc.absoluteThreshold)

// 			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
// 			row := []interface{}{
// 				tc.n,
// 				tc.a,
// 				tc.percentageLeavesLayerThreshold,
// 				elapsedTime1,
// 				elapsedTime2,
// 				tc.absoluteThreshold,
// 				tc.noOfSubsecrets,
// 			}

// 			if !crypto_protocols.CompareUint16s(secretKey,
// 				recoveredKey) {
// 				log.Println(tc)
// 				log.Fatalln(err)
// 				continue
// 			}
// 			data = append(data, row)
// 			fmt.Println("Generation:", elapsedTime1)
// 			fmt.Println("Reconstruction:", elapsedTime2)
// 			fmt.Println("")
// 		}
// 		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(tc.a) + ".csv"
// 		err, _ = files.CreateFile(csvFileName)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}
// 		err = files.WriteToCSVFile(csvFileName, data)
// 		if err != nil {
// 			fmt.Println("Error in writing to the CSV file", err)
// 		}
// 	}
// }

// func EvaluateTwoLayeredAdditiveOptUsedIndisRecoverySecretSizeBinExt(
// 	cfg *configuration.SimulationConfig,
// 	mainDir string) {
// 	testCases, dirSubstr := GenerateTestCases(69, 1, false, cfg)
// 	csvDir := mainDir + dirSubstr
// 	err, _ := files.CreateDirectory(csvDir)
// 	if err != nil {
// 		fmt.Println("Error creating directory:", err)
// 		return
// 	}

// 	secretSizes := []int{2047, 4095, 8191, 16383, 32767, 65535}
// 	// secretSizes := []int{15, 31, 63, 127, 255, 511, 1023}
// 	var f shamir.Field
// 	f.InitializeTables()

// 	var data [][]interface{}
// 	topData := []interface{}{
// 		"Trustees",
// 		"Anonymity Set Size",
// 		"Leaves Threshold",
// 		"Time taken for secret sharing",
// 		"Time taken for secret recovery",
// 		"Absolute Threshold",
// 		"Subsecrets",
// 	}
// 	data = append(data, topData)
// 	totalSimulations := cfg.Iterations * cfg.Iterations
// 	for _, tc := range testCases {
// 		for _, skSize := range secretSizes {
// 			secretKeyBytes, err := crypto_protocols.GenerateRandomBytes(skSize)
// 			if err != nil {
// 				log.Fatalln(err)
// 			}
// 			secretKey := shamir.KeyBytesToKeyUint16s(secretKeyBytes)
// 			for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
// 				fmt.Println("Trustees:", tc.n)
// 				fmt.Println("Anonymity:", obtainedNumber)
// 				fmt.Println("Absolute:", tc.absoluteThreshold)
// 				fmt.Println("Subsecrets:", tc.noOfSubsecrets)
// 				fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

// 				startTime1 := time.Now()
// 				subsecrets, leavesData, parentSubsecrets, xUsedCoords, err :=
// 					secretbe.GenerateAdditiveTwoLayeredOptIndisShares(f, tc.n,
// 						secretKey, tc.absoluteThreshold,
// 						tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

// 				if err != nil {
// 					log.Println(tc)
// 					log.Fatalln(err)
// 					continue
// 				}

// 				sharePackets, maxSharesPerPerson, err := secretbe.GetAdditiveSharePackets(f,
// 					secretKey, tc.n, tc.absoluteThreshold,
// 					leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

// 				if err != nil {
// 					log.Println(tc)
// 					log.Fatalln(err)
// 					continue
// 				}
// 				anonymityPackets, err := secretbe.GetAdditiveAnonymityPackets(
// 					sharePackets,
// 					tc.a, maxSharesPerPerson, len(secretKey),
// 					&xUsedCoords)

// 				if err != nil {
// 					log.Println(tc)
// 					log.Fatalln(err)
// 					continue
// 				}
// 				elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

// 				accessOrder := utils.GenerateIndicesSet(tc.a)
// 				utils.Shuffle(accessOrder)
// 				// fmt.Println(accessOrder)

// 				startTime2 := time.Now()

// 				recoveredKey := secretbe.AdditiveOptUsedIndisSecretRecoveryParallelized(f,
// 					anonymityPackets, accessOrder,
// 					tc.absoluteThreshold)

// 				elapsedTime2 := int(time.Since(startTime2).Nanoseconds())
// 				row := []interface{}{
// 					tc.n,
// 					tc.a,
// 					tc.percentageLeavesLayerThreshold,
// 					elapsedTime1,
// 					elapsedTime2,
// 					tc.absoluteThreshold,
// 					tc.noOfSubsecrets,
// 				}

// 				if !crypto_protocols.CompareUint16s(secretKey,
// 					recoveredKey) {
// 					log.Println(tc)
// 					log.Fatalln(err)
// 					continue
// 				}
// 				data = append(data, row)
// 				fmt.Println("Generation:", elapsedTime1)
// 				fmt.Println("Reconstruction:", elapsedTime2)
// 				fmt.Println("")
// 			}
// 			csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(skSize) + ".csv"
// 			err, _ = files.CreateFile(csvFileName)
// 			if err != nil {
// 				log.Fatalln(err)
// 			}
// 			err = files.WriteToCSVFile(csvFileName, data)
// 			if err != nil {
// 				fmt.Println("Error in writing to the CSV file", err)
// 			}
// 		}
// 	}
// }
