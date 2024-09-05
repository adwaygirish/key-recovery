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

func BenchmarkBasicHashedSecretRecoveryBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateBenchmarkTestCases(cfg)
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
	maxSize := 400
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
	noOfSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < noOfSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
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
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonPackets, accessOrder, secretKeyHash)
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
			if err != nil {
				log.Fatalln(err)
				continue
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

func BenchmarkBasicHashedSecretRecoveryAlternateBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateBenchmarkTestCases(cfg)
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
	maxSize := 400
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
	noOfSimulations := cfg.Iterations * cfg.Iterations
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < noOfSimulations; simulationNumber++ {
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
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
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelizedAlternate(f,
				anonPackets, accessOrder, secretKeyHash, (tc.percentageLeavesLayerThreshold*tc.n)/100)
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
		csvFileName := csvDir + "results-" + strconv.Itoa(tc.a) + "-" + strconv.Itoa(tc.percentageLeavesLayerThreshold) + ".csv"
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

// This is the naive approach of recovering the secret where we have only
// one layer and we have as many shares as the number of trustees
func EvaluateBasicHashedSecretRecoveryBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(1, 2, false, cfg)
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
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			var xUsedCoords []uint16
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
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
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonPackets, accessOrder, secretKeyHash)
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

func EvaluateBasicHashedSecretRecoveryVaryingThresholdBinExt(
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
	for tcIndex := len(testCases) - 1; tcIndex >= 0; tcIndex-- {
		tc := testCases[tcIndex]
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			var xUsedCoords []uint16
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
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
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonPackets, accessOrder, secretKeyHash)
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

func EvaluateBasicHashedSecretRecoveryVaryingTrusteesBinExt(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(4, 2, false, cfg)
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
	for _, tc := range testCases {
		for simulationNumber := 0; simulationNumber < totalSimulations; simulationNumber++ {
			var xUsedCoords []uint16
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
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
			recovered, err := secretbe.BasicHashedSecretRecoveryParallelized(f,
				anonPackets, accessOrder, secretKeyHash)
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
