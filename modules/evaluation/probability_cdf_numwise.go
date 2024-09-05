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
// Additive
// ************************************************************************

// CDF, Total, Additive - with varying anonymity
func EvaluateGetAdditiveProbabilityFixedThNumwiseCDFVAnon(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCases(cfg)
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	// simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		if tc.a != 150 {
			continue
		}
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThNumwiseCDF(
			simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data := FormDataForCSVNumwise(results, results_anon)
			fmt.Println(tc.th)
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

func EvaluateGetAdditiveCompWBAdvObtProbabilityFixedThNumwise(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCases(cfg)
	tc := testCases[len(testCases)-1]
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	// simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	delta_1 := []uint16{10, 20, 30, 40, 50, 60, 70}
	// delta_2 := []uint16{10, 20, 30, 40, 50, 60}
	wbs := []byte{0, 1, 2, 5}
	obts := []byte{99, 95, 90, 85, 80, 70, 60, 50}
	for _, d1 := range delta_1 {
		for _, wb := range wbs {
			for _, obt := range obts {
				fmt.Println(d1, d1, wb, obt)
				results, results_anon, err := probability.GetAdditiveCompWBAdvObtProbabilityFixedThNumwiseCDF(
					simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, d1, d1,
					obt, wb)
				if err != nil {
					log.Fatal(err)
				} else {
					// Get the data that has to be put into the csv file
					data := FormDataForCSVNumwise(results, results_anon)
					fmt.Println(tc.th)
					// Set the name of the file according to the parameters used for
					// generating the result
					csvFileName := GenerateFileNameComparisonAll(csvDir, rng.Intn(10000), tc,
						d1, d1, obt, wb)
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
	}
}

func EvaluateGetAdditiveWBAdvObtProbabilityFixedThNumwise(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCases(cfg)
	tc := testCases[len(testCases)-1]
	fmt.Println(testCases)
	csvDir := mainDir + dirNameSubstr + "/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	// simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	wbs := []byte{0, 1, 2, 5}
	obts := []byte{99, 95, 90, 85, 80, 70, 60, 50}

	for _, wb := range wbs {
		for _, obt := range obts {
			fmt.Println(wb, obt)
			results, results_anon, err := probability.GetAdditiveWBAdvObtProbabilityFixedThNumwiseCDF(
				simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn,
				obt, wb)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data := FormDataForCSVNumwise(results, results_anon)
				fmt.Println(tc.th)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparisonAll(csvDir, rng.Intn(10000), tc,
					uint16(0), uint16(0), obt, wb)
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
}
