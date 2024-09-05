package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/files"
	"key_recovery/modules/probability"
	"log"
	randm "math/rand"
	"time"
)

// ************************************************************************
// Hinted Trustees
// ************************************************************************

// CDF, Total, Hinted Trustees - with varying anonymity
func EvaluateGetHintedTProbabilityFixedThTotalCDFVAnon(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCasesHT(cfg)
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetHintedTProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tc.ht)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameHT(csvDir, rng.Intn(10000), tc)
			fmt.Println(csvFileName)
			err, _ := files.CreateFile(csvFileName)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
			err = files.WriteToCSVFile(csvFileName, data)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
		}
	}
}

// CDF, Total, Hinted Trustees - with varying threshold percentage
func EvaluateGetHintedTProbabilityFixedThTotalCDFVTh(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingThresholdTestCasesHT(cfg)
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetHintedTProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tc.ht)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameHT(csvDir, rng.Intn(10000), tc)
			fmt.Println(csvFileName)
			err, _ := files.CreateFile(csvFileName)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
			err = files.WriteToCSVFile(csvFileName, data)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
		}
	}
}

// CDF, Total, Hinted Trustees - with varying trustees
func EvaluateGetHintedTProbabilityFixedThTotalCDFVTr(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingTrusteesTestCasesHT(cfg)
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetHintedTProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tc.ht)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameHT(csvDir, rng.Intn(10000), tc)
			fmt.Println(csvFileName)
			err, _ := files.CreateFile(csvFileName)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
			err = files.WriteToCSVFile(csvFileName, data)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
		}
	}
}

// CDF, Total, Hinted Trustees - with varying absolute threshold
func EvaluateGetHintedTProbabilityFixedThTotalCDFVAT(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAbsoluteThresholdTestCasesHT(cfg)
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetHintedTProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tc.ht)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameHT(csvDir, rng.Intn(10000), tc)
			fmt.Println(csvFileName)
			err, _ := files.CreateFile(csvFileName)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
			err = files.WriteToCSVFile(csvFileName, data)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
		}
	}
}

// CDF, Total, Hinted Trustees - with varying subsecrets
func EvaluateGetHintedTProbabilityFixedThTotalCDFVSS(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingSubsecretsTestCasesHT(cfg)
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetHintedTProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tc.ht)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameHT(csvDir, rng.Intn(10000), tc)
			fmt.Println(csvFileName)
			err, _ := files.CreateFile(csvFileName)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
			err = files.WriteToCSVFile(csvFileName, data)
			if err != nil {
				log.Fatal("Error in writing to the CSV file", err)
			}
		}
	}
}
