package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("zvadmin %s (built %s, commit %s, %s)\n", Version, BuildDate, GitCommit, runtime.Version())
		},
	}
}
