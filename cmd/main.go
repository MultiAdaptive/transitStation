package main

import (
	"log"
	"os"
	"github.com/MultiAdaptive/transitStation/config"
	"github.com/MultiAdaptive/transitStation/internal/app"
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "transitStation",
	Short: "This is a transit station that is compatible with OP, EigenDA and other DA projects that can support MultiAdaptiveClient DA services",
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the relay server",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig(cfgFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		a := app.NewApp(cfg)
		if err := a.Start(); err != nil {
			log.Fatalf("Application error: %v", err)
		}
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.transitStationConfig.yaml)")
	rootCmd.AddCommand(startCmd)
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
	} else {
		// Search config in home directory with name ".transitStationConfig" (without extension).
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		cfgFile = home + "/.transitStationConfig.yaml"
	}

	// Optionally load environment variables, etc.
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
