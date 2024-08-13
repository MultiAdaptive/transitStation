package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	ServerAddress string `mapstructure:"server_address"`
	EthEndpoint   string `mapstructure:"eth_endpoint"`
	PrivateKey    string `mapstructure:"private_key"`
	NodeGroup     string `mapstructure:"node_group"`
	Namespace     string `mapstructure:"namespace"`
	LogLevel      string `mapstructure:"log_level"` //default is info
	ChainID       uint64 `mapstructure:"chainID"`
	URL           string `mapstructure:"url"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(configFile string) (*Config, error) {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
	}

	viper.SetConfigType("yaml")
	viper.AutomaticEnv() // Read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			log.Printf("Config file not found: %v\n", err)
		} else {
			// Config file was found but another error was produced
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode into struct: %w", err)
	}

	// Default log level
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	if config.PrivateKey == "" || config.URL == "" {
		return nil, fmt.Errorf("private_key and eth_URL must be set in the config file")
	}

	return &config, nil
}
