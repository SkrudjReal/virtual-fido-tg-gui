//go:build !windows

package main

import (
	"fmt"
	"os"
)

func showStartupError(message string) { fmt.Fprintln(os.Stderr, message) }
