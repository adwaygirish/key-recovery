package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/utils"
)

type RunDataType struct {
	n                              int
	a                              int
	absoluteThreshold              int
	noOfSubsecrets                 int
	percentageLeavesLayerThreshold int
}

type RunDataTypeThresholded struct {
	n                              int
	a                              int
	absoluteThreshold              int
	noOfSubsecrets                 int
	percentageLeavesLayerThreshold int
	percentageSubsecretsThreshold  int
}

type RunDataTypeHinted struct {
	n                              int
	a                              int
	absoluteThreshold              int
	noOfSubsecrets                 int
	percentageLeavesLayerThreshold int
	noOfHints                      int
}

func GenerateTestCases(
	param int,
	mode int,
	wc bool,
	cfg *configuration.SimulationConfig) ([]RunDataType, string) {
	var testCases []RunDataType
	var dirNameSubstr string
	baseN := cfg.DefaultTrustees
	baseAbsoluteThreshold := cfg.DefaultAbsoluteThreshold
	baseLeavesPercentageThreshold := cfg.DefaultPercentageThreshold
	baseNoOfSubsecrets := cfg.DefaultNoOfSubsecrets
	baseAnonSetSize := cfg.DefaultAnonymitySetSize
	// Run it for
	if mode == 1 {
		dirNameSubstr = "/add-used-opt-"
	} else {
		dirNameSubstr = "/baseline-"
	}
	switch param {
	// 1 - varying size of the anonymity set
	case 1:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		// Run for bigger sizes only if it is using the optimized version of
		// the paper
		if mode == 1 {
			for i := 20; i <= 50; i++ {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
			for i := 55; i <= 150; i = i + 5 {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		} else {
			for i := 20; i <= 100; i++ {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a"
	// 2 - varying percentage threshold in the leaves
	case 2:
		altAnonSetSize := 30
		for i := 100; i >= 30; i = i - 10 {
			idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, i,
				baseN, baseAbsoluteThreshold)
			testCases = append(testCases, RunDataType{
				n:                              baseN,
				a:                              altAnonSetSize,
				absoluteThreshold:              baseAbsoluteThreshold,
				noOfSubsecrets:                 idealSubsecrets,
				percentageLeavesLayerThreshold: i,
			})
		}
		if mode == 1 {
			for i := 100; i >= 30; i = i - 10 {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, i,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: i,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "perc_th"
	// 3 - varying absolute threshold
	case 3:
		// Vary the absolute threshold
		for i := 3; i <= 6; i++ {
			idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
				baseN, i)
			testCases = append(testCases, RunDataType{
				n:                              baseN,
				a:                              baseAnonSetSize,
				absoluteThreshold:              i,
				noOfSubsecrets:                 idealSubsecrets,
				percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
			})

		}
		dirNameSubstr = dirNameSubstr + "abs_th"
	// Change the number of trustees while keeping the size of the anonymity
	// set constant
	case 4:
		altAnonSetSize := 30
		for i := 20; i <= 30; i = i + 1 {
			idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
				i, baseAbsoluteThreshold)
			testCases = append(testCases, RunDataType{
				n:                              i,
				a:                              altAnonSetSize,
				absoluteThreshold:              baseAbsoluteThreshold,
				noOfSubsecrets:                 idealSubsecrets,
				percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
			})
		}
		if mode == 1 {
			for i := 20; i <= 30; i = i + 1 {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					i, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataType{
					n:                              i,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "n"
	// Vary the number of shares per person
	case 5:
		for i := 2; i <= 5; i = i + 1 {
			// for j := 30; j <= 100; j = j + 10 {
			idealSubsecrets := GetIdealNoOfSubsecrets(i, baseLeavesPercentageThreshold,
				baseN, baseAbsoluteThreshold)
			testCases = append(testCases, RunDataType{
				n:                              baseN,
				a:                              baseAnonSetSize,
				absoluteThreshold:              baseAbsoluteThreshold,
				noOfSubsecrets:                 idealSubsecrets,
				percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
			})
			// }
		}
		dirNameSubstr = dirNameSubstr + "shares_per_person"
	case 6:
		possibleSubsecrets := GetAllPossibleSubsecrets(2, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for _, subsecret := range possibleSubsecrets {
			testCases = append(testCases, RunDataType{
				n:                              baseN,
				a:                              baseAnonSetSize,
				absoluteThreshold:              baseAbsoluteThreshold,
				noOfSubsecrets:                 subsecret,
				percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
			})
		}
		dirNameSubstr = dirNameSubstr + "sub_sec"
	case 7:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		if mode == 1 {
			for i := 155; i <= 300; i = i + 5 {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a"
	case 8:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		if mode == 1 {
			for i := 310; i <= 400; i = i + 10 {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a"
	case 9:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		if mode == 1 {
			for i := 410; i <= 500; i = i + 10 {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a"
	case 11:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		if mode == 1 {
			for i := 510; i <= 600; i = i + 10 {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a"
	default:
		testCases = append(testCases, RunDataType{
			n:                              baseN,
			a:                              baseAnonSetSize,
			absoluteThreshold:              baseAbsoluteThreshold,
			noOfSubsecrets:                 baseNoOfSubsecrets,
			percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
		})
		dirNameSubstr = dirNameSubstr + "basecase"
	}
	if wc {
		dirNameSubstr = dirNameSubstr + "-wc/"
	} else {
		dirNameSubstr = dirNameSubstr + "/"
	}
	fmt.Println(testCases)
	return testCases, dirNameSubstr
}

func GenerateTestCasesThresholded(
	param int,
	mode int,
	wc bool,
	cfg *configuration.SimulationConfig) ([]RunDataTypeThresholded, string) {
	var testCases []RunDataTypeThresholded
	var dirNameSubstr string
	baseN := cfg.DefaultTrustees
	baseAbsoluteThreshold := cfg.DefaultAbsoluteThreshold
	baseLeavesPercentageThreshold := cfg.DefaultPercentageThreshold
	baseNoOfSubsecrets := cfg.DefaultNoOfSubsecrets
	baseAnonSetSize := cfg.DefaultAnonymitySetSize
	// subsecretsThresholds := []int{60, 80}
	subsecretsThresholds := []int{80}
	dirNameSubstr = "/thresholded-used-opt-"
	switch param {
	// 1 - varying size of the anonymity set
	case 1:
		for i := 20; i <= 50; i++ {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		for i := 55; i <= 150; i = i + 5 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}

		dirNameSubstr = dirNameSubstr + "a"
	// 2 - varying percentage threshold in the leaves
	case 2:
		for i := 100; i >= 30; i = i - 10 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, i,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: i,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "perc_th"
	// 3 - varying absolute threshold and number of subsecrets together
	case 3:
		// Vary the absolute threshold
		for i := 3; i <= 6; i++ {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, i)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              i,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "abs_th"
	// Change the number of trustees while keeping the size of the anonymity
	// set constant
	case 4:
		for i := 20; i <= 30; i = i + 1 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					i, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              i,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "n"
	// Vary the number of shares per person
	case 5:
		for i := 2; i <= 5; i = i + 1 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				// for j := 30; j <= 100; j = j + 10 {
				idealSubsecrets := GetIdealNoOfSubsecrets(i, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
				// }
			}
		}
		dirNameSubstr = dirNameSubstr + "shares_per_person"
	case 6:
		possibleSubsecrets := GetAllPossibleSubsecrets(2, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for _, subsecret := range possibleSubsecrets {
			for _, subsecretsThreshold := range subsecretsThresholds {
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 subsecret,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "sub_sec"
	case 7:
		largeAbsoluteThreshold := 3
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, largeAbsoluteThreshold)
		anonymitySetSizes := []int{300, 1000, 3000, 10000}
		for i := 20; i <= 40; i++ {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		for i := 45; i <= 100; i = i + 5 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		for _, i := range anonymitySetSizes {
			for _, subsecretsThreshold := range subsecretsThresholds {
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "-large-a"
	case 8:
		for i := 310; i <= 600; i = i + 10 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a"
	case 9:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		largeAbsoluteThreshold := 3
		as := []int{32, 64, 128, 256, 512}
		for _, i := range as {
			for _, subsecretsThreshold := range subsecretsThresholds {
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		for _, i := range as {
			for _, subsecretsThreshold := range subsecretsThresholds {
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a-exponential"
	case 11:
		for i := 155; i <= 300; i = i + 5 {
			for _, subsecretsThreshold := range subsecretsThresholds {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeThresholded{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					percentageSubsecretsThreshold:  subsecretsThreshold,
				})
			}
		}
	default:
		for _, subsecretsThreshold := range subsecretsThresholds {
			testCases = append(testCases, RunDataTypeThresholded{
				n:                              baseN,
				a:                              baseAnonSetSize,
				absoluteThreshold:              baseAbsoluteThreshold,
				noOfSubsecrets:                 baseNoOfSubsecrets,
				percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				percentageSubsecretsThreshold:  subsecretsThreshold,
			})
		}
		dirNameSubstr = dirNameSubstr + "basecase"
	}
	if wc {
		dirNameSubstr = dirNameSubstr + "-wc-thresholded/"
	} else {
		dirNameSubstr = dirNameSubstr + "-thresholded/"
	}
	fmt.Println(testCases)
	return testCases, dirNameSubstr
}

func GenerateTestCasesHintedT(
	param int,
	mode int,
	wc bool,
	cfg *configuration.SimulationConfig) ([]RunDataTypeHinted, string) {
	var testCases []RunDataTypeHinted
	var dirNameSubstr string
	baseN := cfg.DefaultTrustees
	baseAbsoluteThreshold := cfg.DefaultAbsoluteThreshold
	baseLeavesPercentageThreshold := cfg.DefaultPercentageThreshold
	baseNoOfSubsecrets := cfg.DefaultNoOfSubsecrets
	baseAnonSetSize := cfg.DefaultAnonymitySetSize
	baseTrusteesHint := cfg.DefaultTrusteesHint
	// hintsNums := []int{5, 10}
	hintsNums := []int{5}
	dirNameSubstr = "/hinted-used-opt-"
	switch param {
	// 1 - varying size of the anonymity set
	case 1:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for i := 20; i <= 50; i++ {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		for i := 55; i <= 100; i = i + 5 {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}

		dirNameSubstr = dirNameSubstr + "a"
	// 2 - varying percentage threshold in the leaves
	case 2:
		for i := 100; i >= 30; i = i - 10 {
			for _, h := range hintsNums {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, i,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: i,
					noOfHints:                      h,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "perc_th"
	// 3 - varying absolute threshold
	case 3:
		// Vary the absolute threshold
		for i := 3; i <= 6; i++ {
			for _, h := range hintsNums {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					baseN, i)
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              i,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "abs_th"
	// Change the number of trustees while keeping the size of the anonymity
	// set constant
	case 4:
		for i := 20; i <= 30; i = i + 1 {
			for _, h := range hintsNums {
				idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
					i, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeHinted{
					n:                              i,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "n"
	// Vary the number of shares per person
	case 5:
		for i := 2; i <= 5; i = i + 1 {
			for _, h := range hintsNums {
				// for j := 30; j <= 100; j = j + 10 {
				idealSubsecrets := GetIdealNoOfSubsecrets(i, baseLeavesPercentageThreshold,
					baseN, baseAbsoluteThreshold)
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
				// }
			}
		}
		dirNameSubstr = dirNameSubstr + "shares_per_person"
	case 6:
		possibleSubsecrets := GetAllPossibleSubsecrets(2, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for _, subsecret := range possibleSubsecrets {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              baseAnonSetSize,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 subsecret,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "sub_sec"
	case 7:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for noOfHints := 2; noOfHints <= 12; noOfHints++ {
			testCases = append(testCases, RunDataTypeHinted{
				n:                              baseN,
				a:                              baseAnonSetSize,
				absoluteThreshold:              baseAbsoluteThreshold,
				noOfSubsecrets:                 idealSubsecrets,
				percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
				noOfHints:                      noOfHints,
			})
		}
		dirNameSubstr = dirNameSubstr + "hints"
	case 8:
		largeAbsoluteThreshold := 3
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, largeAbsoluteThreshold)
		for i := 20; i <= 40; i++ {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		for i := 45; i <= 100; i = i + 5 {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		anonymitySetSizes := []int{300, 1000, 3000, 10000}
		for _, i := range anonymitySetSizes {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}

		dirNameSubstr = dirNameSubstr + "-large-a"
	case 9:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for i := 310; i <= 600; i = i + 10 {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}

		dirNameSubstr = dirNameSubstr + "a"
	case 10:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		largeAbsoluteThreshold := 3
		as := []int{32, 64, 128, 256, 512}
		for _, i := range as {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              largeAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		for _, i := range as {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}
		dirNameSubstr = dirNameSubstr + "a-exponential"
	case 11:
		idealSubsecrets := GetIdealNoOfSubsecrets(cfg.DefaultSharesPerPerson, baseLeavesPercentageThreshold,
			baseN, baseAbsoluteThreshold)
		for i := 155; i <= 300; i = i + 5 {
			for _, h := range hintsNums {
				testCases = append(testCases, RunDataTypeHinted{
					n:                              baseN,
					a:                              i,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 idealSubsecrets,
					percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
					noOfHints:                      h,
				})
			}
		}

		dirNameSubstr = dirNameSubstr + "a"
	default:
		testCases = append(testCases, RunDataTypeHinted{
			n:                              baseN,
			a:                              baseAnonSetSize,
			absoluteThreshold:              baseAbsoluteThreshold,
			noOfSubsecrets:                 baseNoOfSubsecrets,
			percentageLeavesLayerThreshold: baseLeavesPercentageThreshold,
			noOfHints:                      baseTrusteesHint,
		})
		dirNameSubstr = dirNameSubstr + "basecase"
	}
	if wc {
		dirNameSubstr = dirNameSubstr + "-wc/"
	} else {
		dirNameSubstr = dirNameSubstr + "/"
	}
	fmt.Println(testCases)
	return testCases, dirNameSubstr
}

func GetIdealNoOfSubsecrets(
	subsecretsCap,
	percentageThreshold,
	trustees,
	absoluteThreshold int,
) int {
	outputSubsecretsNum := 2
	subsecretsNum := 2
	sharesPerSubsecret := utils.FloorDivide(100*absoluteThreshold, percentageThreshold)
	randomShares := -1
	flag := false
	for {
		totalShares := sharesPerSubsecret * subsecretsNum
		if totalShares < trustees {
			subsecretsNum++
			continue
		}
		sharesPerTrustee := int(totalShares / trustees)
		if sharesPerTrustee > subsecretsCap {
			break
		}
		if sharesPerTrustee == subsecretsCap {
			if totalShares%trustees == 0 {
				outputSubsecretsNum++
				break
			}
		}
		if sharesPerTrustee == subsecretsCap-1 && totalShares%trustees != 0 {
			if flag {
				if sharesPerTrustee*trustees-totalShares < randomShares {
					randomShares = sharesPerTrustee*trustees - totalShares
					outputSubsecretsNum = subsecretsNum
				}
			} else {
				randomShares = sharesPerTrustee*trustees - totalShares
				outputSubsecretsNum = subsecretsNum
				flag = true
			}
		}
		subsecretsNum++
	}
	return outputSubsecretsNum
}

func GetLeastNoOfSubsecrets(
	subsecretsCap,
	percentageThreshold,
	trustees,
	absoluteThreshold int,
) int {
	outputSubsecretsNum := 2
	subsecretsNum := 2
	sharesPerSubsecret := utils.FloorDivide(100*absoluteThreshold, percentageThreshold)
	for {
		totalShares := sharesPerSubsecret * subsecretsNum
		if totalShares < trustees {
			subsecretsNum++
			continue
		}
		sharesPerTrustee := int(totalShares / trustees)
		if sharesPerTrustee > subsecretsCap {
			break
		}
		if sharesPerTrustee == subsecretsCap {
			if totalShares%trustees == 0 {
				outputSubsecretsNum++
				break
			}
		}
		if sharesPerTrustee == subsecretsCap-1 && totalShares%trustees != 0 {
			outputSubsecretsNum = subsecretsNum
			break
		}
		subsecretsNum++
	}
	return outputSubsecretsNum
}

func GetAllPossibleSubsecrets(
	subsecretsCap,
	percentageThreshold,
	trustees,
	absoluteThreshold int,
) []int {
	var outputSubsecretsNums []int
	subsecretsNum := 2
	sharesPerSubsecret := utils.FloorDivide(100*absoluteThreshold, percentageThreshold)
	for {
		// The total number of shares including all the subsecrets
		totalShares := sharesPerSubsecret * subsecretsNum
		if totalShares < trustees {
			subsecretsNum++
			continue
		}
		sharesPerTrustee := int(totalShares / trustees)
		// If the shares per trustee is greater than the cap provided
		// break the loop
		if sharesPerTrustee > subsecretsCap {
			break
		}
		// If the shares per trustees is equal to the cap provided
		if sharesPerTrustee == subsecretsCap {
			// Append the number of subsecrets only if the modulo is
			// equal to zero
			if totalShares%trustees == 0 {
				// subsecretsNum++
				outputSubsecretsNums = append(outputSubsecretsNums, subsecretsNum)
			}
			break
		}
		if sharesPerTrustee == subsecretsCap-1 && totalShares%trustees != 0 {
			outputSubsecretsNums = append(outputSubsecretsNums, subsecretsNum)
		}
		subsecretsNum++
	}
	return outputSubsecretsNums
}

func GenerateBenchmarkTestCases(
	cfg *configuration.SimulationConfig,
) ([]RunDataType, string) {
	var testCases []RunDataType
	dirNameSubstr := "/benchmark"
	baseN := cfg.DefaultTrustees
	baseAbsoluteThreshold := cfg.DefaultAbsoluteThreshold
	baseNoOfSubsecrets := cfg.DefaultNoOfSubsecrets
	for pth := 15; pth < 30; pth = pth + 5 {
		if pth < 25 {
			for anon := cfg.DefaultTrustees; anon <= 200; anon = anon + 5 {
				testCases = append(testCases, RunDataType{
					n:                              baseN,
					a:                              anon,
					absoluteThreshold:              baseAbsoluteThreshold,
					noOfSubsecrets:                 baseNoOfSubsecrets,
					percentageLeavesLayerThreshold: pth,
				})
			}
		} else {
			if pth <= 30 {
				for anon := cfg.DefaultTrustees; anon <= 150; anon = anon + 5 {
					testCases = append(testCases, RunDataType{
						n:                              baseN,
						a:                              anon,
						absoluteThreshold:              baseAbsoluteThreshold,
						noOfSubsecrets:                 baseNoOfSubsecrets,
						percentageLeavesLayerThreshold: pth,
					})
				}
			} else {
				for anon := cfg.DefaultTrustees; anon <= 40; anon = anon + 5 {
					testCases = append(testCases, RunDataType{
						n:                              baseN,
						a:                              anon,
						absoluteThreshold:              baseAbsoluteThreshold,
						noOfSubsecrets:                 baseNoOfSubsecrets,
						percentageLeavesLayerThreshold: pth,
					})
				}
			}
		}
	}
	return testCases, dirNameSubstr
}
