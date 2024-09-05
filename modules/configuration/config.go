package configuration

import (
	"os"

	"gopkg.in/yaml.v3"
)

type SimulationConfig struct {
	Iterations                        int `yaml:"iterations"`
	MaxAnonSetSize                    int `yaml:"max_anon_set_size"`
	DefaultTrustees                   int `yaml:"default_trustees"`
	DefaultAnonymitySetSize           int `yaml:"default_anonymity_set_size"`
	DefaultAbsoluteThreshold          int `yaml:"default_absolute_threshold"`
	DefaultNoOfSubsecrets             int `yaml:"default_no_of_subsecrets"`
	DefaultSharesPerPerson            int `yaml:"default_shares_per_person"`
	DefaultPercentageThreshold        int `yaml:"default_percentage_threshold"`
	DefaultSubsecretsThreshold        int `yaml:"default_subsecrets_threshold"`
	DefaultTrusteesHint               int `yaml:"default_trustees_hint"`
	DefaultSharesHint                 int `yaml:"default_shares_hint"`
	DefaultSimulationDistributionNums int `yaml:"simulation_distribution_nums"`
	DefaultSimulationRunNums          int `yaml:"simulation_run_nums"`
}

func NewSimulationConfig(filename string) (*SimulationConfig, error) {
	var cfg SimulationConfig

	data, err := os.ReadFile(filename)

	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &cfg)

	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
