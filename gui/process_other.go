//go:build !windows

package gui

import "os/exec"

func configureCommandWindow(*exec.Cmd) {}
