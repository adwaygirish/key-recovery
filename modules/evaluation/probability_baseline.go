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
// Baseline
// ************************************************************************

// CDF, Total, Baseline - with varying anonymity
func EvaluateGetBaselineProbabilityCDFVAnon(cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCasesBaseline(cfg)
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
	simulations := simulationsDist * simulationsRun

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err :=
			probability.GetBaselineProbabilityCDF(simulations, tc.th, tc.tr, tc.a)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileName(csvDir, rng.Intn(10000), tc)
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

// CDF, Total, Baseline - with varying threshold percentage
func EvaluateGetBaselineProbabilityCDFVTh(cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingThresholdTestCasesBaseline(cfg)
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
	simulations := simulationsDist * simulationsRun

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err :=
			probability.GetBaselineProbabilityCDF(simulations, tc.th, tc.tr, tc.a)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileName(csvDir, rng.Intn(10000), tc)
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

// CDF, Total, Baseline - with varying trustees
func EvaluateGetBaselineProbabilityCDFVTr(cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingTrusteesTestCasesBaseline(cfg)
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
	simulations := simulationsDist * simulationsRun

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err :=
			probability.GetBaselineProbabilityCDF(simulations, tc.th, tc.tr, tc.a)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileName(csvDir, rng.Intn(10000), tc)
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
