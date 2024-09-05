package evaluation

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/files"
	"log"
)

// We assume that a person whistleblows with probability 'p'
// Therefore, the probability of getting caught after k people is
// p (1-p)^k
// When we evaluate the CDF from this, then we get the probability
// of not getting caught as:
// (1-p)^k
// In this function, we simply provide the values of (1-p)^k

func EvaluateNotCaughtProbability(cfg *configuration.SimulationConfig, mainDir string) {
	csvDir := mainDir + "not-caught/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	data := make(map[float64][]float64)
	probabilities := []float64{0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7}
	for _, p := range probabilities {
		data[p] = make([]float64, cfg.DefaultAnonymitySetSize)
		val := float64(1)
		probs := make([]float64, 0)
		for k := 0; k < cfg.DefaultAnonymitySetSize; k++ {
			probs = append(probs, val)
			val = val * (1 - p)
		}
		copy(data[p], probs)
	}
	output := FormDataForCSVFloat(data)
	// Set the name of the file according to the parameters used for
	// generating the result
	csvFileName := csvDir + "not-caught.csv"
	err, _ = files.CreateFile(csvFileName)
	if err != nil {
		log.Fatal("Error in writing to the CSV file", err)
	}
	err = files.WriteToCSVFile(csvFileName, output)
	if err != nil {
		log.Fatal("Error in writing to the CSV file", err)
	}
}

func EvaluateObtainSecretProbability(cfg *configuration.SimulationConfig, mainDir string) {
	csvDir := mainDir + "obtain-secret/"
	err, _ := files.CreateDirectory(csvDir)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	data := make(map[float64][]float64)
	probabilities := []float64{0.999, 0.99, 0.97, 0.95, 0.90, 0.85, 0.80, 0.7}
	for _, p := range probabilities {
		data[p] = make([]float64, cfg.DefaultAnonymitySetSize)
		val := float64(1)
		probs := make([]float64, 0)
		for k := 0; k < cfg.DefaultAnonymitySetSize; k++ {
			probs = append(probs, val)
			val = val * (p)
		}
		copy(data[p], probs)
	}
	output := FormDataForCSVFloat(data)
	// Set the name of the file according to the parameters used for
	// generating the result
	csvFileName := csvDir + "obtain-secret.csv"
	err, _ = files.CreateFile(csvFileName)
	if err != nil {
		log.Fatal("Error in writing to the CSV file", err)
	}
	err = files.WriteToCSVFile(csvFileName, output)
	if err != nil {
		log.Fatal("Error in writing to the CSV file", err)
	}
}
