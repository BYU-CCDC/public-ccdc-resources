package utils

import (
	"os"
	"time"

	"github.com/charmbracelet/log"
)

var (
	Logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    false,
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
		Prefix:          "👾",
	})

	// Add a debug flag
	DebugMode = false
)

// Function to enable debug mode
func EnableDebugMode() {
	DebugMode = true
}
