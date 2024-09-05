package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/files"
	"key_recovery/modules/utils"
	"log"
	randm "math/rand"
	"time"
)

func EvaluateTrusteesExpectedProbability(cfg *configuration.SimulationConfig, mainDir string) {
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

	gamma := cfg.DefaultSharesPerPerson
	alpha := cfg.DefaultAbsoluteThreshold
	tau := cfg.DefaultPercentageThreshold
	nT := cfg.DefaultTrustees

	for _, tc := range testCases {
		probabilities := make([]float64, 0)
		extra := 0
		for nTRec := 0; nTRec <= nT; nTRec++ {
			beta_eta := tc.hlpn
			M := nTRec*gamma - alpha*beta_eta
			Mtotal := nTRec * gamma
			m := beta_eta + 1
			rs := make([]int, 0)
			rs_total := make([]int, 0)
			eta := int(float64(100*alpha)/float64(tc.th) - float64(100*alpha)/float64(tau))
			extra = eta
			r := (alpha * 100 / tau) + eta - alpha
			r_total := (alpha * 100 / tau) + eta
			for i := 0; i < beta_eta; i++ {
				rs = append(rs, r)
				rs_total = append(rs_total, r_total)
			}
			rs = append(rs, (nT*gamma - ((100*alpha/tau)+eta)*beta_eta))
			rs_total = append(rs_total, (nT*gamma - ((100*alpha/tau)+eta)*beta_eta))
			sigma_expected := GetExpectedCount(M, m, rs)
			sigma_total := GetExpectedCount(Mtotal, m, rs_total)
			// fmt.Println(sigma_total, nT*gamma, nTRec*gamma)
			probability := float64(sigma_expected) / float64(sigma_total)
			probabilities = append(probabilities, probability)
		}
		data := FormExpectedDataForCSV(probabilities, probabilities)
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

func GetExpectedCount(M, m int, rs []int) int {
	summation := 0
	allIndices := utils.GenerateIndicesSet(m)
	for subsetSize := 0; subsetSize < m; subsetSize++ {
		subsets := utils.GenerateSubsetsOfSize(allIndices, subsetSize)
		for _, subset := range subsets {
			rSum := 0
			upper := M + m - 1
			lower := m - 1
			for _, ind := range subset {
				rSum += rs[ind] + 1
			}
			upper -= rSum
			if upper < lower {
				continue
			} else {
				val := utils.GetCombination(upper, lower)
				if subsetSize%2 == 1 {
					val = val * (-1)
				}
				summation += val
			}
		}
	}
	// fmt.Println(summation)
	return summation
}

func EvaluateExpectedProbability(cfg *configuration.SimulationConfig, mainDir string) {
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

	recoveryProbabilities := make(map[int][]float64)

	// First store the probabilities with respect to the trustees only
	for _, tc := range testCases {
		alpha := tc.at
		tau := tc.th
		nT := tc.tr
		gamma := utils.CeilDivide(utils.FloorDivide(alpha*100, tau)*tc.hlpn, nT)
		probabilities := make([]float64, 0)
		// extra := 0
		for nTRec := 0; nTRec <= nT; nTRec++ {
			beta_eta := tc.hlpn
			M := nTRec*gamma - alpha*beta_eta
			Mtotal := nTRec * gamma
			m := beta_eta + 1
			rs := make([]int, 0)
			rs_total := make([]int, 0)
			eta := int(float64(100*alpha)/float64(tc.th) - float64(100*alpha)/float64(tau))
			// fmt.Println(eta)
			// extra = eta
			r := (alpha * 100 / tau) + eta - alpha
			r_total := utils.FloorDivide(alpha*100, tau) + eta
			for i := 0; i < beta_eta; i++ {
				rs = append(rs, r)
				rs_total = append(rs_total, r_total)
			}
			rs = append(rs,
				nT*gamma-(utils.FloorDivide(100*alpha, tau)+eta)*beta_eta)
			rs_total = append(rs_total,
				nT*gamma-(utils.FloorDivide(100*alpha, tau)+eta)*beta_eta)
			sigma_expected := GetExpectedCount(M, m, rs)
			sigma_total := GetExpectedCount(Mtotal, m, rs_total)
			// fmt.Println(sigma_total, nT*gamma, nTRec*gamma)
			probability := float64(sigma_expected) / float64(sigma_total)
			probabilities = append(probabilities, probability)
		}
		outputTrusteesProbabilities := make([]float64, len(probabilities))
		copy(outputTrusteesProbabilities, probabilities)
		recoveryProbabilities[tc.th] = outputTrusteesProbabilities

		for _, rr := range recoveryProbabilities[tc.th] {
			if rr > float64(1) {
				fmt.Println("Wrong probability")
			}
		}
		// fmt.Println(recoveryProbabilities[tc.th])
	}

	// Next, find the probability of recovering the secret after contacting
	// nRec people
	for _, tc := range testCases {
		fmt.Println(tc.th)
		overallProbabilities := make([]float64, 0)
		n := tc.a
		nT := tc.tr
		for nRec := 0; nRec <= n; nRec++ {
			overallProbability := float64(0)
			for nTRec := 0; nTRec <= nT; nTRec++ {
				// if nTRec > nRec {
				// 	break
				// }
				recoveryProbability := recoveryProbabilities[tc.th][nTRec]
				combNum1 := utils.GetLargeCombination(nT, nTRec)
				combNum2 := utils.GetLargeCombination((n - nT), (nRec - nTRec))
				combDen := utils.GetLargeCombination(n, nRec)
				numerators := make([]int, 0)
				denominators := make([]int, 0)

				numerators = append(numerators, combNum1[0]...)
				numerators = append(numerators, combNum2[0]...)
				numerators = append(numerators, combDen[1]...)

				denominators = append(denominators, combNum1[1]...)
				denominators = append(denominators, combNum2[1]...)
				denominators = append(denominators, combDen[0]...)
				// fmt.Println(combNum1, combNum2, combDen)

				contactProbability := float64(0)
				if !(utils.IsInSlice(numerators, 0) && utils.IsInSlice(denominators, 0)) {
					contactProbability = utils.GetFraction(numerators, denominators)
				}

				if contactProbability > float64(1) {
					fmt.Println("wrong probability")
					fmt.Println(nT, nTRec)
					fmt.Println((n - nT), (nRec - nTRec), recoveryProbability, nRec)
					fmt.Println(combNum1)
					fmt.Println(combNum2)
					fmt.Println(combDen)
				}

				overallProbability += contactProbability *
					(recoveryProbability)
			}
			overallProbabilities =
				append(overallProbabilities, (overallProbability))
		}
		data := FormExpectedDataForCSV(overallProbabilities, overallProbabilities)
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
