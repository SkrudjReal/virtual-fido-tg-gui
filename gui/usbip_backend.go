package gui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Prefer the separately installed Microsoft-signed USB/IP driver package.
func installedUSBIPDir() string {
	for _, root := range []string{os.Getenv("ProgramW6432"), os.Getenv("ProgramFiles")} {
		if root == "" {
			continue
		}
		dir := filepath.Join(root, "USBip")
		if info, err := os.Stat(filepath.Join(dir, "usbip.exe")); err == nil && !info.IsDir() {
			return dir
		}
	}
	return ""
}

func usbipBackend() (string, bool) {
	return installedUSBIPDir(), true
}

func runUSBIP(dir string, args ...string) ([]byte, error) {
	if dir == "" {
		return nil, fmt.Errorf("signed USBip driver is not installed; open Setup & Drivers and click Install signed USBip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "usbip.exe"), args...)
	configureCommand(cmd)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

func attachedPort(output []byte, modern bool) (string, error) {
	port, err := strconv.Atoi(strings.TrimSpace(string(output)))
	minimum := 0
	if modern {
		minimum = 1
	}
	if err != nil || port < minimum || port > 255 {
		return "", fmt.Errorf("invalid USB/IP attach response: %s", strings.TrimSpace(string(output)))
	}
	return strconv.Itoa(port), nil
}

var portLine = regexp.MustCompile(`(?m)^\s*Port\s+(\d+):`)

func hasPort(output []byte, port string) bool {
	for _, match := range portLine.FindAllSubmatch(output, -1) {
		number, _ := strconv.Atoi(string(match[1]))
		if strconv.Itoa(number) == port {
			return true
		}
	}
	return false
}
