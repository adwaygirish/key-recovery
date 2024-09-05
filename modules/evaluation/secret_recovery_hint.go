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
func EvaluateTwoLayeredHintedTOptUsedIndisRecovery(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(1, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords,
				tc.noOfHints)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingThreshold(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(2, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingAT(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(1, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingTrustees(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(4, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingSS(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(6, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingHints(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(7, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords, 5)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryLargeAnon(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(7, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords,
				tc.noOfHints)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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

func EvaluateTwoLayeredHintedTOptUsedIndisRecoveryExponential(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCasesHintedT(11, 1, false, cfg)
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
				secret.GenerateAdditiveTwoLayeredOptIndisShares(g, tc.n,
					secretKey, randSeedShares, tc.absoluteThreshold,
					tc.noOfSubsecrets, tc.percentageLeavesLayerThreshold)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}

			sharePackets, maxSharesPerPerson, encryptionLength, err := secret.GetHintedTSharePackets(g,
				randSeedShares, secretKey, tc.n, tc.absoluteThreshold,
				leavesData, subsecrets, parentSubsecrets, &xUsedCoords,
				tc.noOfHints)

			if err != nil {
				log.Println(tc)
				log.Fatalln(err)
				continue
			}
			anonymityPackets, err := secret.GetHintedTAnonymityPackets(g,
				randSeedShares, sharePackets,
				tc.a, maxSharesPerPerson,
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

			recoveredKey := secret.HintedTOptUsedIndisSecretRecoveryParallelized(g,
				randSeedShares,
				anonymityPackets, accessOrder,
				tc.absoluteThreshold)

			elapsedTime2 := int(time.Since(startTime2).Nanoseconds())

			if !crypto_protocols.CheckValuesEqual(secretKey,
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
