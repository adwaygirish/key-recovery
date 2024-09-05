package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/utils"
	"strconv"
)

type ProbEval struct {
	l    int
	th   int
	tr   int
	a    int
	at   int
	hlpn int
}

type ProbEvalUpTh struct {
	l    int
	th   int
	uth  int
	tr   int
	a    int
	at   int
	hlpn int
}

type ProbEvalHintedT struct {
	l    int
	th   int
	ht   int
	tr   int
	a    int
	at   int
	hlpn int
}

func FormDataForCSV(input1, input2 map[int]int) ([][]interface{}, int, int) {
	var output [][]interface{}
	topData := []interface{}{
		"Size required to recover",
		"No. of cases",
		"No. of cases in anonymity",
	}
	output = append(output, topData)
	sum1 := 0
	sum2 := 0
	for size, cases := range input1 {
		row := []interface{}{
			size,
			cases,
			input2[size],
		}
		sum1 += cases
		sum2 += input2[size]
		output = append(output, row)
	}
	return output, sum1, sum2
}

func FormDataForCSVFloat(input1 map[float64][]float64) [][]interface{} {
	var output [][]interface{}
	topData := []interface{}{
		"No. of people",
		"Probability per person",
		"Cumulative probability",
	}
	output = append(output, topData)
	for key, vals := range input1 {
		fmt.Println(key, "----", vals)
		for ind, v := range vals {
			row := []interface{}{
				ind,
				key,
				v,
			}
			output = append(output, row)
		}
	}
	return output
}

func FormDataForCSVNumwise(input1, input2 map[int]int) [][]interface{} {
	var output [][]interface{}
	topData := []interface{}{
		"Size required to recover",
		"No. of cases",
		"No. of cases in anonymity",
	}
	output = append(output, topData)
	for size, cases := range input1 {
		row := []interface{}{
			size,
			cases,
			input2[size],
		}
		output = append(output, row)
	}
	return output
}

func FormExpectedDataForCSV(expectedData,
	expectedDataAnon []float64) [][]interface{} {
	var output [][]interface{}
	topData := []interface{}{
		"Size required to recover",
		"Probability (trustees)",
		"Probability (anonymity)",
	}
	output = append(output, topData)
	for ind, prob := range expectedData[1:] {
		row := []interface{}{
			ind + 1,
			prob,
			expectedDataAnon[ind+1],
		}
		output = append(output, row)
	}
	return output
}

// ************************************************************************
// Baseline
// ************************************************************************

// Generate the data for running the simulation for varying threshold in the
// above layer
func GetVaryingAnonymityTestCasesBaseline(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-baseline-an"
	l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
	var output []ProbEval
	as := []int{30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150}
	for _, a := range as {
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying threshold in the
// leaves layer
func GetVaryingThresholdTestCasesBaseline(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-baseline-th"
	l := 2
	tr := cfg.DefaultTrustees
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	var output []ProbEval
	ths := []int{30, 40, 50, 60, 70, 80, 90}

	for _, th := range ths {
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying trustees
func GetVaryingTrusteesTestCasesBaseline(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-baseline-tr"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// hlpn := cfg.DefaultNoOfSubsecrets
	var output []ProbEval
	var trs []int
	for tr := 10; tr <= cfg.DefaultAnonymitySetSize; tr = tr + 5 {
		trs = append(trs, tr)
	}
	for _, tr := range trs {
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// ************************************************************************
// Additive
// ************************************************************************

// Generate the data for running the simulation for varying threshold in the
// above layer
func GetVaryingAnonymityTestCases(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-an"
	l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
	var output []ProbEval
	// as := []int{30, 40, 50, 60, 70, 80, 90, 100, 300}
	as := []int{30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150}
	for _, a := range as {
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying threshold in the
// above layer
func GetVaryingAnonymityTestCasesExponential(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-an"
	l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
	var output []ProbEval
	as := make([]int, 0)
	base_val := 32
	for i := 0; i < 8; i++ {
		as = append(as, base_val)
		base_val = base_val * 2
	}
	for _, a := range as {
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying threshold in the
// leaves layer
func GetVaryingThresholdTestCases(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-th"
	l := 2
	tr := cfg.DefaultTrustees
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	var output []ProbEval
	ths := []int{30, 40, 50, 60, 70, 80, 90}

	for _, th := range ths {
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying trustees
func GetVaryingTrusteesTestCases(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-tr"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// hlpn := cfg.DefaultNoOfSubsecrets
	var output []ProbEval
	var trs []int
	for tr := 10; tr <= cfg.DefaultAnonymitySetSize; tr = tr + 5 {
		trs = append(trs, tr)
	}
	for _, tr := range trs {
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying absolute threshold
func GetVaryingAbsoluteThresholdTestCases(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-at"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	// hlpn := cfg.DefaultNoOfSubsecrets
	tr := cfg.DefaultTrustees
	var output []ProbEval
	atvals := []int{3, 4, 5, 6, 7, 8}
	for _, at := range atvals {
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying subsecrets
func GetVaryingSubsecretsTestCases(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-ss"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// hlpn := cfg.DefaultNoOfSubsecrets
	tr := cfg.DefaultTrustees
	// hlpns := []int{3, 4, 5, 6, 7, 8, 9, 10}
	hlpns := GetAllPossibleSubsecrets(2, th, tr, at)
	var output []ProbEval
	for _, hlpn := range hlpns {
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying shares
// per person
func GetVaryingSharesPerPersonTestCases(
	cfg *configuration.SimulationConfig,
) ([]ProbEval, string) {
	dirNameSubstr := "p-add-spp"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	tr := cfg.DefaultTrustees
	spps := []int{2, 3, 4, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50}
	var output []ProbEval
	for _, spp := range spps {
		hlpn := GetIdealNoOfSubsecrets(spp, th, tr, at)
		output = append(output, ProbEval{l, th, tr, a, at, hlpn})
	}
	return output, dirNameSubstr
}

func GetVaryingAnonymityTestCasesExpected(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-an"
	// l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	var output []ProbEval
	for extra := 0; extra < 11; extra++ {
		// for extra := 1; extra < 2; extra++ {
		as := []int{50, 100}
		idealShares := utils.FloorDivide(at*100, th)
		modifiedShares := idealShares + extra
		modifiedThreshold := utils.FloorDivide(at*100, modifiedShares)
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, modifiedThreshold, tr, at)
		for _, a := range as {
			output = append(output, ProbEval{2, modifiedThreshold, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

func GetVaryingAnonymityTestCasesExpectedExponential(
	cfg *configuration.SimulationConfig) ([]ProbEval, string) {
	dirNameSubstr := "p-add-an"
	// l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	var output []ProbEval
	for extra := 0; extra < 11; extra++ {
		// as := []int{30, 40, 50, 60, 70, 80, 90, 100, 300}
		as := []int{32, 64, 128, 256}
		idealShares := utils.FloorDivide(at*100, th)
		modifiedShares := idealShares + extra
		modifiedThreshold := utils.FloorDivide(at*100, modifiedShares)
		hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, modifiedThreshold, tr, at)
		for _, a := range as {
			output = append(output, ProbEval{2, modifiedThreshold, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

// ************************************************************************
// Thresholded Trustees
// ************************************************************************

func GetVaryingAnonymityTestCasesUpTh(
	cfg *configuration.SimulationConfig) ([]ProbEvalUpTh, string) {
	dirNameSubstr := "p-thr-an"
	l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	// hlpn := cfg.DefaultNoOfSubsecrets
	hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
	uths := []int{40, 50, 60, 70, 80}
	var output []ProbEvalUpTh
	// as := []int{30, 40, 50, 60, 70, 80, 90, 100, 300, 1000, 3000, 10000}
	as := []int{30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150}
	for _, uth := range uths {
		for _, a := range as {
			output = append(output, ProbEvalUpTh{l, th, uth, tr, a, at,
				hlpn})
		}
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying threshold in the
// above layer
func GetVaryingThresholdTestCasesUpTh(
	cfg *configuration.SimulationConfig) ([]ProbEvalUpTh, string) {
	dirNameSubstr := "p-thr-th"
	l := 2
	tr := cfg.DefaultTrustees
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// hlpn := cfg.DefaultNoOfSubsecrets
	var output []ProbEvalUpTh
	ths := []int{30, 40, 50, 60, 70, 80, 90}
	uths := []int{40, 50, 60, 70, 80}
	for _, uth := range uths {
		for _, th := range ths {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalUpTh{l, th, uth, tr, a, at,
				hlpn})
		}
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying trustees
func GetVaryingTrusteesTestCasesUpTh(
	cfg *configuration.SimulationConfig) ([]ProbEvalUpTh, string) {
	dirNameSubstr := "p-thr-tr"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// ssss := 2
	// hlpn := cfg.DefaultNoOfSubsecrets
	var output []ProbEvalUpTh
	var trs []int
	for tr := 10; tr <= cfg.DefaultAnonymitySetSize; tr = tr + 5 {
		trs = append(trs, tr)
	}
	uths := []int{40, 50, 60, 70, 80}
	for _, uth := range uths {
		for _, tr := range trs {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalUpTh{l, th, uth, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying trustees
func GetVaryingAbsoluteThresholdTestCasesUpTh(
	cfg *configuration.SimulationConfig) ([]ProbEvalUpTh, string) {
	dirNameSubstr := "p-thr-at"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	tr := cfg.DefaultTrustees
	atvals := []int{3, 4, 5, 6, 7, 8}
	var output []ProbEvalUpTh
	uths := []int{40, 50, 60, 70, 80}
	for _, uth := range uths {
		for _, at := range atvals {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalUpTh{l, th, uth, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

// Generate the data for running the simulation for varying subsecrets
func GetVaryingSubsecretsTestCasesUpTh(
	cfg *configuration.SimulationConfig) ([]ProbEvalUpTh, string) {
	dirNameSubstr := "p-thr-ss"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	tr := cfg.DefaultTrustees
	hlpns := GetAllPossibleSubsecrets(2, th, tr, at)
	uths := []int{40, 50, 60, 70, 80}
	var output []ProbEvalUpTh
	for _, uth := range uths {
		for _, hlpn := range hlpns {
			output = append(output, ProbEvalUpTh{l, th, uth, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

// ************************************************************************
// Hinted
// ************************************************************************

func GetVaryingAnonymityTestCasesHT(
	cfg *configuration.SimulationConfig) ([]ProbEvalHintedT, string) {
	dirNameSubstr := "p-hintedT-an"
	l := 2
	th := cfg.DefaultPercentageThreshold
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
	// hts := []int{5, 6, 7, 8, 9, 10}
	hts := []int{5, 10}
	var output []ProbEvalHintedT
	as := []int{30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150}
	// as := []int{30, 40, 50, 60, 70, 80, 90, 100, 300, 1000, 3000, 10000}
	for _, ht := range hts {
		for _, a := range as {
			output = append(output, ProbEvalHintedT{l, th, ht, tr, a, at,
				hlpn})
		}
	}
	return output, dirNameSubstr
}

func GetVaryingThresholdTestCasesHT(
	cfg *configuration.SimulationConfig) ([]ProbEvalHintedT, string) {
	dirNameSubstr := "p-hintedT-th"
	l := 2
	tr := cfg.DefaultTrustees
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// hts := []int{5, 6, 7, 8, 9, 10}
	hts := []int{5, 10}
	var output []ProbEvalHintedT
	ths := []int{30, 40, 50, 60, 70, 80, 90}
	for _, ht := range hts {
		for _, th := range ths {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalHintedT{l, th, ht, tr, a, at,
				hlpn})
		}
	}
	return output, dirNameSubstr
}

func GetVaryingTrusteesTestCasesHT(
	cfg *configuration.SimulationConfig) ([]ProbEvalHintedT, string) {
	dirNameSubstr := "p-hintedT-tr"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	// hts := []int{5, 6, 7, 8, 9, 10}
	hts := []int{5, 10}
	var output []ProbEvalHintedT
	var trs []int
	for tr := 10; tr <= cfg.DefaultAnonymitySetSize; tr = tr + 5 {
		trs = append(trs, tr)
	}
	for _, ht := range hts {
		for _, tr := range trs {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalHintedT{l, th, ht, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

func GetVaryingAbsoluteThresholdTestCasesHT(
	cfg *configuration.SimulationConfig) ([]ProbEvalHintedT, string) {
	dirNameSubstr := "p-hintedT-at"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	tr := cfg.DefaultTrustees
	atvals := []int{3, 4, 5, 6, 7, 8}
	// hts := []int{5, 6, 7, 8, 9, 10}
	hts := []int{5, 10}
	var output []ProbEvalHintedT
	for _, ht := range hts {
		for _, at := range atvals {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalHintedT{l, th, ht, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

func GetVaryingSubsecretsTestCasesHT(
	cfg *configuration.SimulationConfig) ([]ProbEvalHintedT, string) {
	dirNameSubstr := "p-hintedT-ss"
	l := 2
	th := cfg.DefaultPercentageThreshold
	a := cfg.DefaultAnonymitySetSize
	at := cfg.DefaultAbsoluteThreshold
	tr := cfg.DefaultTrustees
	hlpns := GetAllPossibleSubsecrets(2, th, tr, at)
	// hts := []int{5, 6, 7, 8, 9, 10}
	hts := []int{5, 10}
	var output []ProbEvalHintedT
	for _, ht := range hts {
		for _, hlpn := range hlpns {
			output = append(output, ProbEvalHintedT{l, th, ht, tr, a, at, hlpn})
		}
	}
	return output, dirNameSubstr
}

// ************************************************************************
// Miscellaneous
// ************************************************************************

func GenerateCDFInfo(results, results_anon map[int]int,
	trustees, anonymity int) (map[int]int, map[int]int) {
	output := make(map[int]int)
	output_anon := make(map[int]int)
	for i := 1; i <= anonymity; i++ {
		sum := 0
		for j := 1; j <= i; j++ {
			sum += output_anon[j]
		}
		output_anon[i] = sum
	}
	for i := 1; i <= trustees; i++ {
		sum := 0
		for j := 1; j <= i; j++ {
			sum += output_anon[j]
		}
		output_anon[i] = sum
	}
	for i := trustees + 1; i <= anonymity; i++ {
		output[i] = 0
	}
	return output, output_anon
}

func GenerateFileNameUpTh(csvDir string,
	randomNum int, element ProbEvalUpTh) string {
	filename := csvDir + "result-probability-" +
		strconv.Itoa(randomNum) + "-" + strconv.Itoa(element.l) + "-" +
		strconv.Itoa(element.th) + "-" + strconv.Itoa(element.tr) + "-" +
		strconv.Itoa(element.a) + "-" +
		strconv.Itoa(element.hlpn) + "-" +
		strconv.Itoa(element.at) + "-" +
		strconv.Itoa(element.uth) + "-.csv"
	return filename
}

func GenerateFileName(csvDir string,
	randomNum int, element ProbEval) string {
	filename := csvDir + "result-probability-" +
		strconv.Itoa(randomNum) + "-" + strconv.Itoa(element.l) + "-" +
		strconv.Itoa(element.th) + "-" + strconv.Itoa(element.tr) + "-" +
		strconv.Itoa(element.a) + "-" +
		strconv.Itoa(element.hlpn) + "-" +
		strconv.Itoa(element.at) + "-.csv"
	return filename
}

func GenerateFileNameExpected(csvDir string,
	randomNum, extra int, element ProbEval) string {
	filename := csvDir + "result-probability-" +
		strconv.Itoa(randomNum) + "-" + strconv.Itoa(element.l) + "-" +
		strconv.Itoa(element.th) + "-" + strconv.Itoa(element.tr) + "-" +
		strconv.Itoa(element.a) + "-" +
		strconv.Itoa(element.hlpn) + "-" +
		strconv.Itoa(element.at) + "-" +
		strconv.Itoa(extra) + "-.csv"
	return filename
}

func GenerateFileNameHT(csvDir string,
	randomNum int, element ProbEvalHintedT) string {
	filename := csvDir + "result-probability-" +
		strconv.Itoa(randomNum) + "-" + strconv.Itoa(element.l) + "-" +
		strconv.Itoa(element.th) + "-" + strconv.Itoa(element.tr) + "-" +
		strconv.Itoa(element.a) + "-" +
		strconv.Itoa(element.hlpn) + "-" +
		strconv.Itoa(element.at) + "-" +
		strconv.Itoa(element.ht) + "-.csv"
	return filename
}

func GenerateFileNameComparison(csvDir string,
	randomNum int, element ProbEval, d1, d2 uint16) string {
	filename := csvDir + "result-probability-" +
		strconv.Itoa(randomNum) + "-" + strconv.Itoa(element.l) + "-" +
		strconv.Itoa(element.th) + "-" + strconv.Itoa(element.tr) + "-" +
		strconv.Itoa(element.a) + "-" +
		strconv.Itoa(element.hlpn) + "-" +
		strconv.Itoa(element.at) + "-" +
		strconv.Itoa(int(d1)) + "-" +
		strconv.Itoa(int(d2)) + "-.csv"
	return filename
}

func GenerateFileNameComparisonAll(csvDir string,
	randomNum int, element ProbEval, d1, d2 uint16,
	p1, p2 byte) string {
	filename := csvDir + "result-probability-" +
		strconv.Itoa(randomNum) + "-" + strconv.Itoa(element.l) + "-" +
		strconv.Itoa(element.th) + "-" + strconv.Itoa(element.tr) + "-" +
		strconv.Itoa(element.a) + "-" +
		strconv.Itoa(element.hlpn) + "-" +
		strconv.Itoa(element.at) + "-" +
		strconv.Itoa(int(d1)) + "-" +
		strconv.Itoa(int(d2)) + "-" +
		strconv.Itoa(int(p1)) + "-" +
		strconv.Itoa(int(p2)) +
		"-.csv"
	return filename
}

// Generate the data for running the simulation for varying threshold in the
// leaves layer
func GetVaryingThresholdTestCasesSameAnon(cfg *configuration.SimulationConfig) []ProbEval {
	l := 2
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	// ssss := 2
	hlpn := cfg.DefaultNoOfSubsecrets
	var output []ProbEval
	ths := []int{30, 40, 50, 60, 70, 80, 90}

	for _, th := range ths {
		output = append(output, ProbEval{l, th, tr, tr, at, hlpn})
	}
	return output
}

func GetVaryingThresholdTestCasesUpThSameAnon(cfg *configuration.SimulationConfig) []ProbEvalUpTh {
	l := 2
	tr := cfg.DefaultTrustees
	at := cfg.DefaultAbsoluteThreshold
	var output []ProbEvalUpTh
	ths := []int{30, 40, 50, 60, 70, 80, 90}
	uths := []int{40, 60, 80}
	for _, uth := range uths {
		for _, th := range ths {
			hlpn := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, th, tr, at)
			output = append(output, ProbEvalUpTh{l, th, uth, tr, tr, at,
				hlpn})
		}
	}
	return output
}
