package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	crypto_protocols "key_recovery/modules/crypto"
	"key_recovery/modules/files"
	"key_recovery/modules/secret"
	"key_recovery/modules/utils"
	"log"
	"strconv"
	"time"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// This is the worst case evaluation of the secret recovery
// It is the worst case because the user approaches all the people
// with the random blobs first, and then, approaches the people with the
// shares
func EvaluateTwoLayeredThresholdedOptUsedIndisRecovery(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(1, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThreshold(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(2, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingAT(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(3, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrustees(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(4, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSS(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(6, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryLargeAnon(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(7, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryExponential(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesThresholded(11, 1, false, cfg)
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
		"Time taken for secret sharing",
		"Time taken for secret recovery",
		"Absolute Threshold",
		"Subsecrets",
		"Subsecrets Threshold",
	}
	data = append(data, topData)
	totalSimulations := cfg.Iterations * cfg.Iterations
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
				secret.GenerateTwoLayeredOptIndisShares(g, tc.n, secretKey, randSeedShares,
					tc.absoluteThreshold, tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold,
					tc.percentageSubsecretsThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetThresholdedSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			anonymityPackets, err := secret.GetThresholdedAnonymityPackets(g,
				randSeedShares, sharePackets, tc.a, maxSharesPerPerson,
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

			// recoveredKey := secret.ThOptUsedIndisSecretRecovery(g,
			// 	randSeedShares,
			// 	anonymityPackets, accessOrder,
			// 	tc.absoluteThreshold)
			recoveredKey := secret.ThOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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
