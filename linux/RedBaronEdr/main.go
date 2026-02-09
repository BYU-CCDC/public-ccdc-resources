package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"red-baron-edr/installer"
	"red-baron-edr/kubearmor_provider"
	"red-baron-edr/yara"
	"strings"
	"sync"
	"syscall"

	"github.com/charmbracelet/log"

	"red-baron-edr/utils"
)

func main() {

	utils.Logger.Info("Red Baron EDR, Copyright 2025 Noah Magill.")
	utils.Logger.Info("red-team has fancy tools, why can't we?")

	// Parse command-line flags
	runFlag := flag.String("run", "all", "Specify which wait group(s) to run (ka, auditd,yara). Separate multiple values with commas.")
	debugFlag := flag.Bool("debug", false, "Enable debug mode")
	installFlag := flag.Bool("install", false, "Run the installer")
	flag.Parse()

	// Determine default run options if no flags are passed
	if flag.NFlag() == 0 {
		// Always include YARA
		*runFlag = "yara"

		// Check if a web server is running
		if isWebServerRunning() {
			*runFlag = "web," + *runFlag
		}

		if _, err := os.Stat("/usr/local/bin/karmor"); err == nil {
			// Check if KubeArmor is installed
			*runFlag = "ka," + *runFlag
		} else if _, err := os.Stat("/etc/audit/auditd.conf"); err == nil {
			// Check if Auditd is configured
			*runFlag = "auditd," + *runFlag
		}
	}

	if *installFlag {
		err := installer.RunInstallation()
		if err != nil {
			utils.Logger.Fatalf("Installation failed: %v", err)
		}
		utils.Logger.Info("Installation completed successfully.")
		os.Exit(0)
	}

	if *debugFlag {
		utils.Logger.SetLevel(log.DebugLevel)
		utils.DebugMode = true
	}

	// Create a context that we can cancel to signal goroutines to stop
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		utils.Logger.Info("Received termination signal, shutting down gracefully...")
		cancel()
	}()

	// Use WaitGroup to manage the selected async threads
	var wg sync.WaitGroup

	runOptions := strings.Split(*runFlag, ",")
	runKa := contains(runOptions, "ka") || contains(runOptions, "all")
	runYara := contains(runOptions, "yara") || contains(runOptions, "all")
	//runWeb := contains(runOptions, "web") || contains(runOptions, "all")

	if runKa {
		utils.Logger.Debug("Started KubeArmor Ingestor")
		wg.Add(1)
		go func() {
			defer wg.Done()
			kubearmor_provider.StartKAIngestor()
		}()
	}

	// Initialize YARA watcher and start monitor if enabled
	if runYara {
		utils.Logger.Info("Started YARA Monitor")
		directories := []string{"/etc", "/usr", "/root", "/home", "/var/www", "/srv", "/opt", "/tmp"}
		if err := yara.InitializeWatcher(directories); err != nil {
			utils.Logger.Errorf("Failed to initialize watcher: %v", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			yara.MonitorYARAFiles(ctx, &wg)
		}()

		// Start scanning processes in a separate goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			yara.ScanProcesses(ctx)
		}()
	}

	// if runWeb {
	// 	utils.Logger.Info("Started Web Monitor")
	// 	wg.Add(1)
	// 	go func() {
	// 		defer wg.Done()
	// 		web_parser.StartWebScan()
	// 	}()

	// }

	// Wait for all listeners and YARA monitor
	wg.Wait()
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == item {
			return true
		}
	}
	return false
}

// Function to check if apache2, nginx, or httpd is running
func isWebServerRunning() bool {
	servers := []string{"apache2", "nginx", "httpd"}
	for _, server := range servers {
		cmd := exec.Command("pgrep", server)
		if err := cmd.Run(); err == nil {
			return true
		}
	}
	return false
}
