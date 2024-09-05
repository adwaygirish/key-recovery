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

// CDF, Total, Additive - same trustess and anon. - with varying threshold
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVThSameAnon(cfg *configuration.SimulationConfig,
	mainDir string) {
	csvDir := mainDir + "csv-prob_add_v_th_same/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums
	// Generate the data over which the simulations will be run
	testCases := GetVaryingThresholdTestCasesSameAnon(cfg)
	fmt.Println(testCases)

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDF(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn)
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

// CDF, Total, Thresholded - same trustess and anon. - with varying threshold
func EvaluateGetThresholdedProbabilityFixedThTotalCDFVThSameAnon(cfg *configuration.SimulationConfig,
	mainDir string) {
	csvDir := mainDir + "csv-prob_thr_v_th_same/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums
	// Generate the data over which the simulations will be run
	testCases := GetVaryingThresholdTestCasesUpThSameAnon(cfg)
	fmt.Println(testCases)

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetThresholdedProbabilityFixedThTotalCDF(
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
