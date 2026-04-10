package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

const collectionStateFile = ".zovark/collection_state.json"

type collectionState struct {
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

func collectionStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, collectionStateFile), nil
}

func readCollectionState() (*collectionState, error) {
	p, err := collectionStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &collectionState{Enabled: false, UpdatedAt: time.Time{}}, nil
		}
		return nil, err
	}
	var s collectionState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeCollectionState(enabled bool) error {
	p, err := collectionStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	s := collectionState{Enabled: enabled, UpdatedAt: time.Now().UTC()}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func collectionCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "collection",
		Short: "Customer-side privacy-preserving collection controls (Ticket 5)",
	}

	root.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show whether local collection export is enabled",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := readCollectionState()
			if err != nil {
				return err
			}
			envOn := os.Getenv("ZOVARK_COLLECTION_ENABLED") == "true" || os.Getenv("ZOVARK_COLLECTION_ENABLED") == "1"
			fmt.Println("Zovark collection (host state file)")
			fmt.Printf("  state_file: ")
			p, _ := collectionStatePath()
			fmt.Println(p)
			fmt.Printf("  file_enabled: %v\n", s.Enabled)
			fmt.Printf("  env ZOVARK_COLLECTION_ENABLED: %v\n", envOn)
			if !s.UpdatedAt.IsZero() {
				fmt.Printf("  last_changed: %s\n", s.UpdatedAt.Format(time.RFC3339))
			}
			fmt.Println("\nDocker profile: docker compose --profile collection up -d fluent-bit")
			fmt.Println("Buffer volume: zovark_collection_buffer → /collection/buffer (read-only in sidecar)")
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "enable",
		Short: "Enable collection flag in local operator state (set ZOVARK_COLLECTION_ENABLED=true in shell/compose)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := writeCollectionState(true); err != nil {
				return err
			}
			fmt.Printf("%sCollection enabled in %s%s\n", colorGreen, collectionStateFile, colorReset)
			fmt.Println("Export anonymized JSONL to the collection buffer and start fluent-bit with profile collection.")
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "disable",
		Short: "Disable collection flag in local operator state",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := writeCollectionState(false); err != nil {
				return err
			}
			fmt.Printf("%sCollection disabled in %s%s\n", colorYellow, collectionStateFile, colorReset)
			return nil
		},
	})

	return root
}
