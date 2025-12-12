package integrity

import (
	"bytes"
	"os/exec"

	"github.com/charmbracelet/log"
)

func StartModule(time string) { // Use PascalCase for exported functions

	log.Info("Started Module Integrity...")

	var out bytes.Buffer
	cmd := exec.Command("which", "systemd")
	cmd.Stdout = &out // Redirect standard output to the buffer

	err := cmd.Run() // Run the command and capture errors

	if err != nil {
		log.Errorf("Error checking for systemd: %v", err)
	} else {
		// Systemd found, perform actions based on its presence
		log.Info("Systemd found")
		startIntegrityCheck()
	}
}

func startIntegrityCheck() {

}
