package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	stagingDir         = ".staging"
	backupPrefix       = ".backup-"
	inferenceContainer = "zovark-inference"
	healthTimeout      = 120 * time.Second
	healthPollInterval = 5 * time.Second
)

func updateCmd() *cobra.Command {
	var skipBenchmark bool
	var modelsDir string

	cmd := &cobra.Command{
		Use:   "update <bundle.zvk>",
		Short: "Apply a .zvk model update bundle with staging and rollback",
		Long: `Extract a .zvk bundle to a staging directory, back up current models,
move staged models into place, verify inference health, and optionally run
the benchmark suite. Automatically rolls back on failure.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(args[0], modelsDir, skipBenchmark)
		},
	}

	cmd.Flags().BoolVar(&skipBenchmark, "skip-benchmark", false, "Skip post-update benchmark validation")
	cmd.Flags().StringVar(&modelsDir, "models-dir", "./models", "Path to the models directory")
	return cmd
}

// bundleManifest represents the manifest.json inside a .zvk bundle.
type bundleManifest struct {
	Version       string `json:"version"`
	BuiltAt       string `json:"built_at"`
	ExpiresAt     string `json:"expires_at"`
	IncludeModels bool   `json:"include_models"`
}

func runUpdate(tarPath string, modelsDir string, skipBenchmark bool) error {
	fmt.Println("ZOVARK MODEL UPDATE")
	fmt.Println("═══════════════════")

	// --- Validate bundle file exists ---
	absBundle, err := filepath.Abs(tarPath)
	if err != nil {
		return fmt.Errorf("cannot resolve bundle path: %w", err)
	}
	info, err := os.Stat(absBundle)
	if err != nil {
		return fmt.Errorf("bundle not found: %s", absBundle)
	}
	fmt.Printf("[1/7] Bundle: %s (%s)\n", filepath.Base(absBundle), formatBytes(info.Size()))

	// --- Compute SHA-256 of the bundle ---
	bundleHash, err := sha256File(absBundle)
	if err != nil {
		return fmt.Errorf("cannot hash bundle: %w", err)
	}
	fmt.Printf("      SHA-256: %s\n", bundleHash)

	// --- Resolve models directory ---
	absModels, err := filepath.Abs(modelsDir)
	if err != nil {
		return fmt.Errorf("cannot resolve models dir: %w", err)
	}
	if err := os.MkdirAll(absModels, 0o755); err != nil {
		return fmt.Errorf("cannot create models dir: %w", err)
	}

	stagingPath := filepath.Join(absModels, stagingDir)
	timestamp := time.Now().UTC().Format("20060102-150405")
	backupPath := filepath.Join(absModels, backupPrefix+timestamp)

	// --- Clean up any previous staging ---
	_ = os.RemoveAll(stagingPath)

	// --- Stage 1: Extract bundle to staging ---
	fmt.Printf("[2/7] Extracting to %s ...\n", stagingPath)
	if err := extractTarGz(absBundle, stagingPath); err != nil {
		_ = os.RemoveAll(stagingPath)
		return fmt.Errorf("extraction failed: %w", err)
	}

	// --- Read and validate manifest ---
	manifest, err := readManifest(stagingPath)
	if err != nil {
		_ = os.RemoveAll(stagingPath)
		return fmt.Errorf("invalid bundle: %w", err)
	}
	fmt.Printf("      Version: %s  Built: %s  Models: %v\n",
		manifest.Version, manifest.BuiltAt, manifest.IncludeModels)

	// Check expiry
	if manifest.ExpiresAt != "" {
		expires, parseErr := time.Parse(time.RFC3339, manifest.ExpiresAt)
		if parseErr == nil && time.Now().After(expires) {
			_ = os.RemoveAll(stagingPath)
			return fmt.Errorf("bundle expired at %s", manifest.ExpiresAt)
		}
	}

	// --- Identify model files in staging ---
	stagedModels, err := findModelFiles(stagingPath)
	if err != nil {
		_ = os.RemoveAll(stagingPath)
		return fmt.Errorf("cannot scan staged models: %w", err)
	}
	if len(stagedModels) == 0 {
		_ = os.RemoveAll(stagingPath)
		return fmt.Errorf("no model files found in bundle (expected *.gguf, *.bin, or *.tar.gz)")
	}
	fmt.Printf("      Found %d model file(s):\n", len(stagedModels))
	for _, m := range stagedModels {
		fmt.Printf("        - %s\n", filepath.Base(m))
	}

	// --- Stage 2: Back up current models ---
	existingModels, _ := findModelFiles(absModels)
	if len(existingModels) > 0 {
		fmt.Printf("[3/7] Backing up %d current model(s) to %s\n", len(existingModels), filepath.Base(backupPath))
		if err := os.MkdirAll(backupPath, 0o755); err != nil {
			_ = os.RemoveAll(stagingPath)
			return fmt.Errorf("cannot create backup dir: %w", err)
		}
		for _, model := range existingModels {
			dst := filepath.Join(backupPath, filepath.Base(model))
			if err := moveFile(model, dst); err != nil {
				// Restore any already-moved files
				restoreBackup(backupPath, absModels)
				_ = os.RemoveAll(stagingPath)
				return fmt.Errorf("backup failed for %s: %w", filepath.Base(model), err)
			}
		}
	} else {
		fmt.Println("[3/7] No existing models to back up")
	}

	// --- Stage 3: Move staged models into models dir ---
	fmt.Printf("[4/7] Installing %d model(s) ...\n", len(stagedModels))
	for _, staged := range stagedModels {
		dst := filepath.Join(absModels, filepath.Base(staged))
		if err := moveFile(staged, dst); err != nil {
			fmt.Printf("      %sInstall failed: %v%s\n", colorRed, err, colorReset)
			fmt.Println("      Rolling back ...")
			rollbackModels(backupPath, absModels)
			_ = os.RemoveAll(stagingPath)
			return fmt.Errorf("model install failed, rolled back")
		}
	}

	// Clean staging
	_ = os.RemoveAll(stagingPath)

	// --- Stage 4: Restart inference container ---
	fmt.Printf("[5/7] Restarting inference container (%s) ...\n", inferenceContainer)
	restartErr := restartContainer(inferenceContainer)
	if restartErr != nil {
		// Container might not exist (host-mode inference). Try restarting host LLM service.
		fmt.Printf("      Container restart failed: %v\n", restartErr)
		fmt.Println("      Attempting host LLM service restart ...")
		restartErr = restartHostLLM()
	}
	if restartErr != nil {
		fmt.Printf("      %sWARNING: Could not restart inference. Verify manually.%s\n", colorYellow, colorReset)
		fmt.Println("      Continuing with health check ...")
	}

	// --- Stage 5: Health check ---
	fmt.Printf("[6/7] Waiting for inference to become healthy (timeout %s) ...\n", healthTimeout)
	if err := waitForInferenceHealth(healthTimeout); err != nil {
		fmt.Printf("      %sHealth check failed: %v%s\n", colorRed, err, colorReset)
		fmt.Println("      Rolling back ...")
		rollbackModels(backupPath, absModels)
		_ = restartContainer(inferenceContainer)
		return fmt.Errorf("inference unhealthy after update, rolled back: %w", err)
	}
	fmt.Printf("      %sInference healthy%s\n", colorGreen, colorReset)

	// --- Stage 6: Benchmark ---
	if skipBenchmark {
		fmt.Println("[7/7] Benchmark skipped (--skip-benchmark)")
	} else {
		fmt.Println("[7/7] Running benchmark validation ...")
		if err := runBenchmarkValidation(); err != nil {
			fmt.Printf("      %sBenchmark failed: %v%s\n", colorRed, err, colorReset)
			fmt.Println("      Rolling back ...")
			rollbackModels(backupPath, absModels)
			_ = restartContainer(inferenceContainer)
			// Wait for old models to load
			_ = waitForInferenceHealth(healthTimeout)
			return fmt.Errorf("benchmark failed after update, rolled back: %w", err)
		}
		fmt.Printf("      %sBenchmark passed%s\n", colorGreen, colorReset)
	}

	fmt.Println("═══════════════════")
	fmt.Printf("%sUpdate to %s complete.%s\n", colorGreen, manifest.Version, colorReset)
	fmt.Printf("Backup preserved at: %s\n", backupPath)
	fmt.Println("To remove the backup after verification: rm -rf", backupPath)
	return nil
}

// ─── TAR/GZIP EXTRACTION ────────────────────────────────────────────

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a gzip file: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		// Sanitize: reject paths with ".." to prevent directory traversal
		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") {
			return fmt.Errorf("invalid path in archive: %s", header.Name)
		}

		target := filepath.Join(dst, cleanName)

		// Ensure the target is within the destination directory
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dst)) {
			return fmt.Errorf("path escapes destination: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)&0o755)
			if err != nil {
				return err
			}
			// Limit copy to declared size to prevent decompression bombs
			if _, err := io.Copy(outFile, io.LimitReader(tr, header.Size)); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}

// ─── MANIFEST ────────────────────────────────────────────────────────

func readManifest(stagingPath string) (*bundleManifest, error) {
	data, err := os.ReadFile(filepath.Join(stagingPath, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("manifest.json not found in bundle: %w", err)
	}
	var m bundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid manifest.json: %w", err)
	}
	if m.Version == "" {
		return nil, fmt.Errorf("manifest.json missing version field")
	}
	return &m, nil
}

// ─── MODEL FILE DISCOVERY ────────────────────────────────────────────

// findModelFiles returns paths to model files (.gguf, .bin) and image
// archives (.tar.gz) found directly in the given directory (non-recursive
// for the top level, but checks one level deep for staging subdirs).
func findModelFiles(dir string) ([]string, error) {
	var models []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)

		// Skip hidden/meta files
		if strings.HasPrefix(name, ".") {
			continue
		}

		if strings.HasSuffix(lower, ".gguf") ||
			strings.HasSuffix(lower, ".bin") ||
			(strings.HasSuffix(lower, ".tar.gz") && !strings.HasPrefix(lower, "zovark-update")) {
			models = append(models, filepath.Join(dir, name))
		}
	}
	return models, nil
}

// ─── FILE OPERATIONS ─────────────────────────────────────────────────

// moveFile attempts os.Rename first (same filesystem, instant). Falls back
// to copy+delete for cross-device moves.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	// Cross-device fallback: copy then remove
	return copyAndRemove(src, dst)
}

func copyAndRemove(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	in.Close()

	return os.Remove(src)
}

// ─── BACKUP / ROLLBACK ──────────────────────────────────────────────

func restoreBackup(backupDir, modelsDir string) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(backupDir, e.Name())
		dst := filepath.Join(modelsDir, e.Name())
		_ = moveFile(src, dst)
	}
}

func rollbackModels(backupDir, modelsDir string) {
	// Remove newly installed models
	newModels, _ := findModelFiles(modelsDir)
	for _, m := range newModels {
		_ = os.Remove(m)
	}

	// Restore from backup
	if backupDir != "" {
		restoreBackup(backupDir, modelsDir)
		fmt.Printf("      Restored models from %s\n", filepath.Base(backupDir))
	}
}

// ─── CONTAINER MANAGEMENT ────────────────────────────────────────────

func restartContainer(name string) error {
	cmd := exec.Command("docker", "restart", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func restartHostLLM() error {
	// Try systemd service first (Linux appliance), then Docker container.
	if out, err := exec.Command("systemctl", "restart", "zovark-inference").CombinedOutput(); err == nil {
		fmt.Println("      Restarted zovark-inference via systemctl")
		return nil
	} else {
		_ = out
	}

	// Fallback: restart via docker compose
	if err := restartContainer("zovark-inference"); err == nil {
		fmt.Println("      Restarted zovark-inference container")
		return nil
	}

	return fmt.Errorf("could not restart LLM service — restart manually")
}

// ─── HEALTH CHECK ────────────────────────────────────────────────────

func waitForInferenceHealth(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	// Check LLM health endpoint — try FAST endpoint first, then BASE_URL
	llmURL := os.Getenv("ZOVARK_LLM_ENDPOINT_FAST")
	if llmURL == "" {
		llmURL = os.Getenv("ZOVARK_LLM_ENDPOINT")
	}
	if llmURL == "" {
		llmURL = os.Getenv("ZOVARK_LLM_BASE_URL")
	}
	if llmURL == "" {
		llmURL = "http://localhost:8080"
	}
	// Strip trailing API paths to get base URL for health check
	llmURL = strings.TrimSuffix(llmURL, "/v1/chat/completions")
	llmURL = strings.TrimSuffix(llmURL, "/")

	// Health check via /health endpoint (llama-server standard)
	checkURL := llmURL + "/health"

	for time.Now().Before(deadline) {
		cmd := exec.Command("curl", "-sf", "--max-time", "5", checkURL)
		if err := cmd.Run(); err == nil {
			return nil
		}

		remaining := time.Until(deadline).Truncate(time.Second)
		fmt.Printf("      Waiting ... (%s remaining)\n", remaining)
		time.Sleep(healthPollInterval)
	}
	return fmt.Errorf("inference did not become healthy within %s", timeout)
}

// ─── BENCHMARK VALIDATION ────────────────────────────────────────────

// runBenchmarkValidation invokes the zvadmin benchmark as a subprocess.
// This reuses the exact same benchmark logic without duplicating code.
func runBenchmarkValidation() error {
	// Find our own executable path to call "zvadmin benchmark"
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find own executable: %w", err)
	}

	cmd := exec.Command(self, "benchmark")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("benchmark exited with error: %w", err)
	}
	return nil
}

// ─── UTILITIES ───────────────────────────────────────────────────────

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func formatBytes(b int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
