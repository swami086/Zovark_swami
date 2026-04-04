package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func breakglassCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "breakglass",
		Short: "Emergency break-glass authentication",
	}
	cmd.AddCommand(breakglassSetPasswordCmd())
	return cmd
}

func breakglassSetPasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-password",
		Short: "Generate bcrypt hash for break-glass password",
		Run:   runSetPassword,
	}
}

func runSetPassword(cmd *cobra.Command, args []string) {
	fmt.Print("Enter break-glass password: ")
	pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("Confirm password: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	if string(pw1) != string(pw2) {
		fmt.Println("Passwords do not match")
		os.Exit(1)
	}

	if len(pw1) < 12 {
		fmt.Println("Password must be at least 12 characters")
		os.Exit(1)
	}

	hash, err := bcrypt.GenerateFromPassword(pw1, 12)
	if err != nil {
		fmt.Printf("Error generating hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Set this in your .env file:")
	fmt.Printf("ZOVARK_BREAKGLASS_PASSWORD_HASH=%s\n", string(hash))
	fmt.Println()
	fmt.Println("Then restart the API: docker compose restart api")
}
