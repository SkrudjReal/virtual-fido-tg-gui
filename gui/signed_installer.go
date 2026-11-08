package gui

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const signedInstallerName = "USBip-0.9.8.1-x64.exe"
const signedInstallerSHA256 = "38cad6d4432b52d5bb9409d9ad03b72fdffc4ada4cd3a48fbeca1a2752a8518a"

// Unmodified official release asset, pinned to its published GitHub digest.
//
//go:embed signed_driver/USBip-0.9.8.1-x64.exe
var signedInstaller []byte

func prepareSignedInstaller(dir string) (string, error) {
	path := filepath.Join(dir, signedInstallerName)
	if err := os.WriteFile(path, signedInstaller, 0700); err != nil {
		return "", err
	}
	return path, verifySignedInstallerHash(path)
}

func verifySignedInstallerHash(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != signedInstallerSHA256 {
		return fmt.Errorf("signed USBip installer integrity check failed")
	}
	return nil
}

func verifySignedInstaller(path string) error {
	if err := verifySignedInstallerHash(path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Authenticode verification requires Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Pass the path as data, never interpolate it into PowerShell code.
	cmd := exec.CommandContext(ctx, getSystemCmd("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command",
		`$ErrorActionPreference='Stop'; if ((Get-AuthenticodeSignature -LiteralPath $env:VFIDO_SIGNED_INSTALLER).Status -ne 'Valid') { throw 'USBip installer Authenticode signature is not trusted' }`)
	cmd.Env = append(os.Environ(), "VFIDO_SIGNED_INSTALLER="+path)
	configureCommand(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("USBip signature verification failed: %w: %s", err, out)
	}
	return nil
}

func installSignedDriver() error {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("this signed driver package requires Windows x64")
	}
	dir, err := os.MkdirTemp("", "virtual-fido-signed-setup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path, err := prepareSignedInstaller(dir)
	if err != nil {
		return err
	}
	if err := verifySignedInstaller(path); err != nil {
		return err
	}
	// Keep the official interactive wizard and prohibit an automatic restart.
	cmd := exec.Command(path, "/NORESTART", "/TYPE=compact", "/TASKS=vcredist")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("USBip setup did not complete: %w", err)
	}
	if installedUSBIPDir() == "" {
		return fmt.Errorf("USBip setup finished, but the client was not found in Program Files/USBip")
	}
	return nil
}
