package cmd

import (
	"fmt"
	"key_recovery/modules/configuration"
	"key_recovery/modules/evaluation"
	"key_recovery/modules/files"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

var (
	evalType         int
	varyingParameter int
	verbose          bool
)

var rootCmd = &cobra.Command{
	Use:   "key_recovery",
	Short: "Key Recovery",
	Long:  `Running and evaluating the defined key recovery mechanism`,
	Run: func(cmd *cobra.Command, args []string) {
		if verbose {
			fmt.Println("Verbose mode enabled")
		}
		configFilePath := "modules/configuration/config.yaml"
		cfg, err := configuration.NewSimulationConfig(configFilePath)
		if err != nil {
			fmt.Println("Error in accessing the config file", err)
			fmt.Println(err)
		}

		// Get the current timestamp
		timestamp := time.Now().Unix()

		mainDir := "/" + strconv.Itoa(int(timestamp)) + "/"

		switch {
		case evalType%3 == 0:
			mainDir = "results-computation-parallelized" + mainDir
		case evalType%3 == 1:
			mainDir = "results-probability" + mainDir
		case evalType%3 == 2:
			mainDir = "results-computation-parallelized-bin-ext" + mainDir
		default:
			mainDir = "results-computation-parallelized" + mainDir
		}

		// Create the parent directory
		err, _ = files.CreateDirectory(mainDir)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}

		evaluation.Evaluate(cfg, mainDir, evalType, varyingParameter)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().IntVarP(&evalType, "type", "t", 0, "Evaluation type - either the run evaluates the computation cost or the probability")
	rootCmd.Flags().IntVarP(&varyingParameter, "parameter", "p", 0, "Parameter to be varied during evaluation")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose mode")
}
