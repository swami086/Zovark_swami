package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// ============================================================
// SECRETS MANAGEMENT — VAULT INTEGRATION (Issue #3)
// ============================================================

// VaultClient provides secret reading from HashiCorp Vault.
type VaultClient struct {
	addr      string
	token     string
	client    *http.Client
	cache     map[string]string
	cacheMu   sync.RWMutex
	enabled   bool
	stopChan  chan struct{}
}

var vaultClient *VaultClient

// initVault initializes the Vault client from environment variables.
// Falls back to env vars when Vault is not configured.
func initVault() {
	addr := getEnvOrDefault("VAULT_ADDR", "")
	token := getEnvOrDefault("VAULT_TOKEN", "")

	if addr == "" {
		log.Println("Vault not configured (VAULT_ADDR not set). Using environment variables for secrets.")
		vaultClient = &VaultClient{enabled: false}
		return
	}

	vaultClient = &VaultClient{
		addr:     addr,
		token:    token,
		client:   &http.Client{Timeout: 5 * time.Second},
		cache:    make(map[string]string),
		enabled:  true,
		stopChan: make(chan struct{}),
	}

	// Load initial secrets
	vaultClient.refreshSecrets()

	// Start periodic refresh
	go vaultClient.periodicRefresh()

	log.Printf("Vault client initialized: addr=%s", addr)
}

// stopVault stops the periodic secret refresh.
func stopVault() {
	if vaultClient != nil && vaultClient.enabled {
		close(vaultClient.stopChan)
	}
}

// periodicRefresh refreshes secrets from Vault every 5 minutes.
func (vc *VaultClient) periodicRefresh() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-vc.stopChan:
			return
		case <-ticker.C:
			vc.refreshSecrets()
		}
	}
}

// refreshSecrets reads all HYDRA secrets from Vault and updates the cache.
func (vc *VaultClient) refreshSecrets() {
	secretPaths := map[string]string{
		"database_url":      "secret/data/hydra/database",
		"jwt_secret":        "secret/data/hydra/jwt",
		"litellm_master_key": "secret/data/hydra/litellm",
		"redis_url":         "secret/data/hydra/redis",
	}

	for key, path := range secretPaths {
		value, err := vc.readSecret(path, key)
		if err != nil {
			log.Printf("Vault: failed to read %s from %s: %v", key, path, err)
			continue
		}
		if value != "" {
			vc.cacheMu.Lock()
			vc.cache[key] = value
			vc.cacheMu.Unlock()
		}
	}

	log.Printf("Vault: secrets refreshed (%d cached)", len(vc.cache))
}

// readSecret reads a single secret from Vault's KV v2 engine.
func (vc *VaultClient) readSecret(path, key string) (string, error) {
	url := fmt.Sprintf("%s/v1/%s", vc.addr, path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", vc.token)

	resp, err := vc.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(body))
	}

	var vaultResp struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return "", fmt.Errorf("failed to parse vault response: %w", err)
	}

	if val, ok := vaultResp.Data.Data[key]; ok {
		if s, ok := val.(string); ok {
			return s, nil
		}
	}

	// Try "value" as a generic key
	if val, ok := vaultResp.Data.Data["value"]; ok {
		if s, ok := val.(string); ok {
			return s, nil
		}
	}

	return "", nil
}

// GetSecret retrieves a secret from Vault cache, falling back to environment variables.
func GetSecret(key, envVar, fallback string) string {
	if vaultClient != nil && vaultClient.enabled {
		vaultClient.cacheMu.RLock()
		if val, ok := vaultClient.cache[key]; ok && val != "" {
			vaultClient.cacheMu.RUnlock()
			return val
		}
		vaultClient.cacheMu.RUnlock()
	}

	// Fallback to environment variable
	return getEnvOrDefault(envVar, fallback)
}
