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

func BenchmarkBasicHashedSecretRecovery(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateBenchmarkTestCases(cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretKeyHash := crypto_protocols.GetSHA256(secretKeyBytes)
	maxSize := 400

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
			shareVals := secret.GenerateSharesPercentage(g, tc.percentageLeavesLayerThreshold, tc.n,
				secretKey, randSeedShares)
			anonymityShareVals, _ := secret.GetDisAnonymitySet(g,
				tc.n, tc.a, maxSize, randSeedShares, shareVals)
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()
			// _, err := secret.BasicHashedSecretRecovery(g,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err := secret.BasicHashedSecretRecoveryParallelized(g,
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

func BenchmarkBasicHashedSecretRecoveryAlternate(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateBenchmarkTestCases(cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretKeyHash := crypto_protocols.GetSHA256(secretKeyBytes)
	maxSize := 400

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
			shareVals := secret.GenerateSharesPercentage(g, tc.percentageLeavesLayerThreshold, tc.n,
				secretKey, randSeedShares)
			anonymityShareVals, _ := secret.GetDisAnonymitySet(g,
				tc.n, tc.a, maxSize, randSeedShares, shareVals)
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()
			// _, err := secret.BasicHashedSecretRecovery(g,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err := secret.BasicHashedSecretRecoveryParallelizedAlternate(g,
				anonymityShareVals, accessOrder, secretKeyHash, (tc.percentageLeavesLayerThreshold*tc.n)/100)
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
func EvaluateBasicHashedSecretRecovery(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(1, 2, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretKeyHash := crypto_protocols.GetSHA256(secretKeyBytes)
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
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage", tc.percentageLeavesLayerThreshold)
			startTime1 := time.Now()
			shareVals := secret.GenerateSharesPercentage(g, tc.percentageLeavesLayerThreshold, tc.n,
				secretKey, randSeedShares)
			anonymityShareVals, _ := secret.GetDisAnonymitySet(g,
				tc.n, tc.a, maxSize, randSeedShares, shareVals)
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()
			// _, err := secret.BasicHashedSecretRecovery(g,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err := secret.BasicHashedSecretRecoveryParallelizedUint16(g,
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

func EvaluateBasicHashedSecretRecoveryVaryingThreshold(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(2, 2, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretKeyHash := crypto_protocols.GetSHA256(secretKeyBytes)
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
			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			shareVals := secret.GenerateSharesPercentage(g, tc.percentageLeavesLayerThreshold, tc.n,
				secretKey, randSeedShares)
			anonymityShareVals, _ := secret.GetDisAnonymitySet(g,
				tc.n, tc.a, maxSize, randSeedShares, shareVals)
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()
			// _, err := secret.BasicHashedSecretRecovery(g,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err := secret.BasicHashedSecretRecoveryParallelizedUint16(g,
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

func EvaluateBasicHashedSecretRecoveryVaryingTrustees(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	testCases, dirSubstr := GenerateTestCases(4, 2, false, cfg)
	csvDir := mainDir + dirSubstr
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	g := edwards25519.NewBlakeSHA256Ed25519()
	randSeedShares := g.RandomStream()
	secretKey := g.Scalar().Pick(randSeedShares)
	secretKeyBytes := crypto_protocols.ConvertKeyToBytes(secretKey)
	secretKeyHash := crypto_protocols.GetSHA256(secretKeyBytes)
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

			fmt.Println("Trustees:", tc.n)
			fmt.Println("Anonymity:", tc.a)
			fmt.Println("Percentage:", tc.percentageLeavesLayerThreshold)

			startTime1 := time.Now()
			shareVals := secret.GenerateSharesPercentage(g, tc.percentageLeavesLayerThreshold, tc.n,
				secretKey, randSeedShares)
			anonymityShareVals, _ := secret.GetDisAnonymitySet(g,
				tc.n, tc.a, maxSize, randSeedShares, shareVals)
			elapsedTime1 := int(time.Since(startTime1).Nanoseconds())

			accessOrder := utils.GenerateIndicesSet(tc.a)
			utils.Shuffle(accessOrder)

			startTime2 := time.Now()
			// _, err := secret.BasicHashedSecretRecovery(g,
			// 	anonymityShareVals, accessOrder, secretKeyHash)
			_, err := secret.BasicHashedSecretRecoveryParallelizedUint16(g,
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
