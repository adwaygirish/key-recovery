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
// Thresholded
// ************************************************************************

// CDF, Total, Thresholded - with varying anonymity
func EvaluateGetThresholdedProbabilityFixedThTotalCDFVAnon(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCasesUpTh(cfg)
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
		results, results_anon, err := probability.GetThresholdedProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.uth, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameUpTh(csvDir, rng.Intn(10000), tc)
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

// CDF, Total, Thresholded - with varying threshold percentage
func EvaluateGetThresholdedProbabilityFixedThTotalCDFVTh(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingThresholdTestCasesUpTh(cfg)
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
		results, results_anon, err := probability.GetThresholdedProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.uth, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameUpTh(csvDir, rng.Intn(10000), tc)
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

// CDF, Total, Thresholded - with varying trustees
func EvaluateGetThresholdedProbabilityFixedThTotalCDFVTr(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingTrusteesTestCasesUpTh(cfg)
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
		results, results_anon, err := probability.GetThresholdedProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.uth, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameUpTh(csvDir, rng.Intn(10000), tc)
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

// CDF, Total, Thresholded - with varying trustees
func EvaluateGetThresholdedProbabilityFixedThTotalCDFVAT(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAbsoluteThresholdTestCasesUpTh(cfg)
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
		results, results_anon, err := probability.GetThresholdedProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.uth, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameUpTh(csvDir, rng.Intn(10000), tc)
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

// CDF, Total, Thresholded - with varying trustees
func EvaluateGetThresholdedProbabilityFixedThTotalCDFVSS(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingSubsecretsTestCasesUpTh(cfg)
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
		results, results_anon, err := probability.GetThresholdedProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.uth, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameUpTh(csvDir, rng.Intn(10000), tc)
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
