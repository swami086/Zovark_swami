package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version   = "v3.2.0"
	BuildDate = "dev"
	GitCommit = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zvadmin",
		Short: "Zovark Sovereign Appliance Admin CLI",
		Long:  "Host-side management tool for the Zovark SOC appliance. Runs outside Docker.",
	}

	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(queueCmd())
	rootCmd.AddCommand(breakglassCmd())
	rootCmd.AddCommand(benchmarkCmd())
	rootCmd.AddCommand(updateCmd())
	rootCmd.AddCommand(diagnoseCmd())
	rootCmd.AddCommand(alertsCmd())
	rootCmd.AddCommand(modelCheckCmd())
	rootCmd.AddCommand(dedupHealthCmd())
	rootCmd.AddCommand(troubleshootCmd())
	rootCmd.AddCommand(collectionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
