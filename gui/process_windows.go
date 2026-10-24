//go:build windows

package gui

import (
	"os/exec"
	"syscall"
)

func configureCommandWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
