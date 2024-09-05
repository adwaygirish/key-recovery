package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/files"
	"key_recovery/modules/probability"
	"key_recovery/modules/utils"
	"log"
	randm "math/rand"
	"time"
)

// ************************************************************************
// Additive
// ************************************************************************

// CDF, Total, Additive - with varying anonymity
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVAnon(cfg *configuration.SimulationConfig, mainDir string) {
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
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	for _, tc := range testCases {
		fmt.Println(tc)
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
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

// CDF, Total, Additive - with varying anonymity (exponential)
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVAnonExponential(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCasesExponential(cfg)
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
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
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

// CDF, Total, Additive - with varying threshold percentage
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVTh(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingThresholdTestCases(cfg)
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
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
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

// CDF, Total, Additive - with varying trustees
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVTr(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingTrusteesTestCases(cfg)
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
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
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

// CDF, Total, Additive - with varying absolute threshold
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVAT(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAbsoluteThresholdTestCases(cfg)
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
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
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

// CDF, Total, Additive - with varying subsecrets
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVSS(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingSubsecretsTestCases(cfg)
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
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
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

// CDF, Total, Additive - with varying shares per packet
func EvaluateGetAdditiveProbabilityFixedThTotalCDFVSPP(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingSharesPerPersonTestCases(cfg)
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
		sharesPerSS := utils.FloorDivide((100 * tc.at), tc.th)
		totalShares := sharesPerSS * tc.hlpn
		sharesPerPerson := totalShares / tc.tr
		fmt.Println(tc)
		results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			// Making a small tweak as compared to others
			// Setting the parametet layers to the shares per person so
			// that there is no need to write another function
			tc.l = sharesPerPerson
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

// CDF, Total, Additive - with varying anonymity
func EvaluateGetAdditiveExpectedProbabilityFixedThTotalCDFVAnon(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCasesExpected(cfg)
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
		for extra := 0; extra < 11; extra++ {
			results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, extra, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameExpected(csvDir, rng.Intn(10000), extra, tc)
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

// CDF, Total, Additive - with varying anonymity
func EvaluateGetAdditiveExpectedProbabilityFixedThTotalCDFVAnonExponential(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	testCases, dirNameSubstr := GetVaryingAnonymityTestCasesExpectedExponential(cfg)
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
		for extra := 0; extra < 11; extra++ {
			results, results_anon, err := probability.GetAdditiveProbabilityFixedThTotalCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, extra, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameExpected(csvDir, rng.Intn(10000), extra, tc)
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

func EvaluateGetUserCompProbabilityCDFParallelized(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr1 := "user"

	csvDir1 := mainDir + dirNameSubstr1 + "/"

	err, _ := files.CreateDirectory(csvDir1)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	delta_1 := []uint16{0, 10, 20, 30, 40, 50, 60, 70}
	delta_2 := []uint16{10, 20, 30, 40, 50, 60}

	// Evaluation for user
	for _, d1 := range delta_1 {
		for _, d2 := range delta_2 {
			if d1 > uint16(20) || d2 > uint16(20) {
				continue
			}
			results, results_anon, err := probability.GetCompProbabilityCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, d1, d2)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparison(csvDir1, rng.Intn(10000), tc, d1, d2)
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

func EvaluateGetAdvCompProbabilityCDFParallelized(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr2 := "adv"

	csvDir2 := mainDir + dirNameSubstr2 + "/"

	err, _ := files.CreateDirectory(csvDir2)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	delta_1 := []uint16{0, 10, 20, 30, 40, 50, 60, 70}
	delta_2 := []uint16{10, 20, 30, 40, 50, 60}

	// Evaluation for adversary
	for _, d1 := range delta_1 {
		for _, d2 := range delta_2 {
			if d1 < uint16(30) || d2 < uint16(30) {
				continue
			}
			results, results_anon, err := probability.GetCompProbabilityCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, d1, d2)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparison(csvDir2, rng.Intn(10000), tc, d1, d2)
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

func EvaluateGetCompProbabilityCDFParallelized(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr1 := "comp"

	csvDir1 := mainDir + dirNameSubstr1 + "/"

	err, _ := files.CreateDirectory(csvDir1)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	delta_1 := make([]uint16, 0)
	for i := 0; i < 80; i = i + 10 {
		delta_1 = append(delta_1, uint16(i))
	}

	// Evaluation for user
	for _, d1 := range delta_1 {
		results, results_anon, err := probability.GetCompProbabilityCDFParallelized(
			simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, d1, d1)
		if err != nil {
			log.Fatal(err)
		} else {
			// Get the data that has to be put into the csv file
			data, sum1, sum2 := FormDataForCSV(results, results_anon)
			fmt.Println(tc.th, sum1, sum2)
			// Set the name of the file according to the parameters used for
			// generating the result
			csvFileName := GenerateFileNameComparison(csvDir1, rng.Intn(10000), tc, d1, d1)
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

func EvaluateGetCompWBAdvObtProbabilityCDFParallelized(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr1 := "comp"

	csvDir1 := mainDir + dirNameSubstr1 + "/"

	err, _ := files.CreateDirectory(csvDir1)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	delta_1 := make([]uint16, 0)
	for i := 10; i < 80; i = i + 10 {
		delta_1 = append(delta_1, uint16(i))
	}
	wbs := []byte{0, 1, 2, 5}
	obts := []byte{100, 99, 95, 90, 85, 80, 70, 60, 50}

	// Evaluation for user
	for _, d1 := range delta_1 {
		for _, wb := range wbs {
			for _, obt := range obts {
				fmt.Println(d1, wb, obt)
				results, results_anon, err := probability.GetCompWBAdvObtProbabilityCDFParallelized(
					simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, d1, d1,
					obt, wb)
				if err != nil {
					log.Fatal(err)
				} else {
					// Get the data that has to be put into the csv file
					data, sum1, sum2 := FormDataForCSV(results, results_anon)
					fmt.Println(tc.th, sum1, sum2)
					// Set the name of the file according to the parameters used for
					// generating the result
					csvFileName := GenerateFileNameComparisonAll(csvDir1, rng.Intn(10000), tc, d1, d1, obt, wb)
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

func EvaluateGetWBAdvObtProbabilityCDFParallelized(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr1 := "comp"

	csvDir1 := mainDir + dirNameSubstr1 + "/"

	err, _ := files.CreateDirectory(csvDir1)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	wbs := []byte{0, 1, 2, 5}
	obts := []byte{100, 99, 95, 90, 85, 80, 70, 60, 50}

	// Evaluation for user

	for _, wb := range wbs {
		for _, obt := range obts {
			fmt.Println(wb, obt)
			results, results_anon, err := probability.GetWBAdvObtProbabilityCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, obt, wb)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparisonAll(csvDir1, rng.Intn(10000), tc, uint16(0), uint16(0), obt, wb)
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

func EvaluateGetCompWBAdvObtBaselineProbabilityCDF(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr1 := "comp-baseline"

	csvDir1 := mainDir + dirNameSubstr1 + "/"

	err, _ := files.CreateDirectory(csvDir1)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	delta_1 := make([]uint16, 0)
	for i := 10; i < 80; i = i + 10 {
		delta_1 = append(delta_1, uint16(i))
	}
	wbs := []byte{0, 1, 2, 5}
	obts := []byte{100, 99, 95, 90, 85, 80, 70, 60, 50}

	// Evaluation for user
	simulations := simulationsDist * simulationsRun
	for _, d1 := range delta_1 {
		for _, wb := range wbs {
			for _, obt := range obts {
				fmt.Println(d1, wb, obt)
				results, results_anon, err := probability.GetCompWBAdvObtBaselineProbabilityCDF(
					simulations, tc.th, tc.tr, tc.a, d1, d1,
					obt, wb)
				if err != nil {
					log.Fatal(err)
				} else {
					// Get the data that has to be put into the csv file
					data, sum1, sum2 := FormDataForCSV(results, results_anon)
					fmt.Println(tc.th, sum1, sum2)
					// Set the name of the file according to the parameters used for
					// generating the result
					csvFileName := GenerateFileNameComparisonAll(csvDir1, rng.Intn(10000), tc, d1, d1, obt, wb)
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

func EvaluateGetWBAdvObtBaselineProbabilityCDF(
	cfg *configuration.SimulationConfig,
	mainDir string) {
	// Generate the data over which the simulations will be run
	tc := ProbEval{
		l:    2,
		th:   50,
		tr:   20,
		a:    150,
		at:   3,
		hlpn: 6,
	}
	dirNameSubstr1 := "comp-baseline"

	csvDir1 := mainDir + dirNameSubstr1 + "/"

	err, _ := files.CreateDirectory(csvDir1)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	source := randm.NewSource(time.Now().UnixNano())
	rng := randm.New(source)
	simulationsDist := cfg.DefaultSimulationDistributionNums
	simulationsRun := cfg.DefaultSimulationRunNums

	wbs := []byte{0, 1, 2, 5}
	obts := []byte{100, 99, 95, 90, 85, 80, 70, 60, 50}

	// Evaluation for user
	simulations := simulationsDist * simulationsRun
	for _, wb := range wbs {
		for _, obt := range obts {
			fmt.Println(wb, obt)
			results, results_anon, err := probability.GetWBAdvObtBaselineProbabilityCDF(
				simulations, tc.th, tc.tr, tc.a, obt, wb)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparisonAll(csvDir1, rng.Intn(10000), tc, uint16(0), uint16(0), obt, wb)
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

func EvaluateGetCompWBAdvObtProbabilityCDFParallelizedAbs(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	for abt := 4; abt <= 6; abt++ {
		cfg.DefaultAbsoluteThreshold = abt
		testCases, _ := GetVaryingAnonymityTestCases(cfg)
		tc := testCases[len(testCases)-1]
		fmt.Println(tc)
		dirNameSubstr1 := "comp"
		csvDir1 := mainDir + dirNameSubstr1 + "/"

		err, _ := files.CreateDirectory(csvDir1)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}

		source := randm.NewSource(time.Now().UnixNano())
		rng := randm.New(source)
		simulationsDist := cfg.DefaultSimulationDistributionNums
		simulationsRun := cfg.DefaultSimulationRunNums
		testCasesWBObt := []struct {
			d1  uint16
			wb  byte
			obt byte
		}{
			{20, 0, 100},
			{40, 1, 50},
		}
		for _, tcwo := range testCasesWBObt {

			fmt.Println(tc.at, tcwo.d1, tcwo.d1, tcwo.wb, tcwo.obt)
			results, results_anon, err := probability.GetCompWBAdvObtProbabilityCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tcwo.d1, tcwo.d1,
				tcwo.obt, tcwo.wb)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparisonAll(csvDir1, rng.Intn(10000), tc,
					tcwo.d1, tcwo.d1, tcwo.obt, tcwo.wb)
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

func EvaluateGetCompWBAdvObtProbabilityCDFParallelizedSS(cfg *configuration.SimulationConfig, mainDir string) {
	// Generate the data over which the simulations will be run
	for abt := 4; abt <= 6; abt++ {
		// cfg.DefaultAbsoluteThreshold = abt
		testCases, _ := GetVaryingAnonymityTestCases(cfg)
		tc := testCases[len(testCases)-1]
		tc.hlpn = abt
		fmt.Println(tc)
		dirNameSubstr1 := "comp"
		csvDir1 := mainDir + dirNameSubstr1 + "/"

		err, _ := files.CreateDirectory(csvDir1)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}

		source := randm.NewSource(time.Now().UnixNano())
		rng := randm.New(source)
		simulationsDist := cfg.DefaultSimulationDistributionNums
		simulationsRun := cfg.DefaultSimulationRunNums
		testCasesWBObt := []struct {
			d1  uint16
			wb  byte
			obt byte
		}{
			{20, 0, 100},
			{40, 1, 50},
		}
		for _, tcwo := range testCasesWBObt {

			fmt.Println(tc.hlpn, tcwo.d1, tcwo.d1, tcwo.wb, tcwo.obt)
			results, results_anon, err := probability.GetCompWBAdvObtProbabilityCDFParallelized(
				simulationsDist, simulationsRun, tc.l, tc.th, tc.tr, tc.a, tc.at, tc.hlpn, tcwo.d1, tcwo.d1,
				tcwo.obt, tcwo.wb)
			if err != nil {
				log.Fatal(err)
			} else {
				// Get the data that has to be put into the csv file
				data, sum1, sum2 := FormDataForCSV(results, results_anon)
				fmt.Println(tc.th, sum1, sum2)
				// Set the name of the file according to the parameters used for
				// generating the result
				csvFileName := GenerateFileNameComparisonAll(csvDir1, rng.Intn(10000), tc,
					tcwo.d1, tcwo.d1, tcwo.obt, tcwo.wb)
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
