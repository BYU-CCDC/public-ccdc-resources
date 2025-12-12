package yara

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"math/rand"
	"time"

	"red-baron-edr/rule_engine2/rule_utils"
	"red-baron-edr/utils"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/process"

	"github.com/hillu/go-yara/v4"
)

var compiledRules *yara.Rules                 // Global variable to hold compiled YARA rules
var scannedHashes = make(map[string]struct{}) // Global map to store MD5 hashes of clean processes

// InitializeYARARules compiles all YARA rules from the "yara_rules" directory.
func InitializeYARARules() *yara.Rules {
	ruleDir := utils.YaraRulesDir
	compiler, err := yara.NewCompiler()
	if err != nil {
		utils.Logger.Errorf("Error creating YARA compiler: %v", err)
		return nil
	}
	utils.Logger.Info("Created YARA compiler")

	files, err := os.ReadDir(ruleDir)
	if err != nil {
		utils.Logger.Errorf("Error reading YARA rules directory: %v", err)
		return nil
	}
	ruleCount := 0 // Counter for loaded rules

	// Compile YARA rules from the rule directory
	for _, file := range files {
		if file.IsDir() || !isYARARuleFile(file.Name()) {
			utils.Logger.Infof("Skipping file: %s", file.Name())
			continue
		}
		ruleFilePath := filepath.Join(ruleDir, file.Name())
		utils.Logger.Debugf("Attempting to compile YARA rule file: %s", ruleFilePath)

		ruleFile, err := os.Open(ruleFilePath)
		if err != nil {
			utils.Logger.Debugf("Error opening YARA rule file %s: %v", ruleFilePath, err)
			continue
		}

		// Add file to the compiler
		if err := compiler.AddFile(ruleFile, ""); err != nil {
			utils.Logger.Errorf("Error compiling YARA rule %s: %v", ruleFilePath, err)
			ruleFile.Close()
			continue
		}
		ruleFile.Close()
		ruleCount++
		utils.Logger.Debugf("Successfully compiled YARA rule file: %s", ruleFilePath)
	}

	if ruleCount == 0 {
		utils.Logger.Errorf("No YARA rules were successfully compiled.")
		return nil
	}

	rules, err := compiler.GetRules()
	if err != nil {
		utils.Logger.Errorf("Error getting compiled YARA rules: %v", err)
		return nil
	}
	utils.Logger.Infof("YARA rules loaded successfully: %d rules", ruleCount)
	return rules
}

// ScanProcesses scans all running processes with YARA rules.
func ScanProcesses(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(40+rand.Intn(21)) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			utils.Logger.Info("Process scanning stopped.")
			return
		case <-ticker.C:
			processes, err := process.Processes()
			if err != nil {
				utils.Logger.Debugf("Error fetching processes: %v", err)
				continue
			}

			utils.Logger.Debugf("Scanning %d processes", len(processes))
			for _, proc := range processes {
				// Check if the process is still running
				if _, err := os.Stat(filepath.Join("/proc", fmt.Sprint(proc.Pid))); os.IsNotExist(err) {
					utils.Logger.Debugf("Process %d no longer exists", proc.Pid)
					continue
				}

				// Filter out kernel processes and kworkers
				if procName, _ := proc.Name(); strings.HasPrefix(procName, "kworker") || strings.HasPrefix(procName, "k") {
					utils.Logger.Debugf("Skipping kernel process %d", proc.Pid)
					continue
				}

				// Check Virtual Memory Size
				if vms, _ := proc.MemoryInfo(); vms.VMS == 0 {
					utils.Logger.Debugf("Skipping process %d with VMS 0", proc.Pid)
					continue
				}

				exePath, err := proc.Exe()
				if err != nil {
					utils.Logger.Debugf("Error fetching executable for process %d: %v", proc.Pid, err)
					continue
				}

				// Skip scanning if the executable is in the excluded directory
				if strings.HasPrefix(exePath, "/opt/redbaronedr/redbaron") {
					utils.Logger.Debugf("Skipping process %d as it is in the excluded directory", proc.Pid)
					continue
				}

				// Construct the path to the executable in /proc
				procExePath := filepath.Join("/proc", fmt.Sprint(proc.Pid), "exe")
				exeFile, err := os.Open(procExePath)
				if err != nil {
					utils.Logger.Debugf("Error opening executable for process %d: %v", proc.Pid, err)
					continue
				}
				defer exeFile.Close()

				// Initialize MD5 hash
				hasher := md5.New()

				// Read the executable file content in chunks
				chunkSize := 10 * 1024 * 1024 // 10MB
				overlapSize := 10 * 1024      // 10KB
				buffer := make([]byte, chunkSize+overlapSize)
				var prevChunk []byte

				for {
					n, err := exeFile.Read(buffer[overlapSize:])
					if err != nil && err != io.EOF {
						utils.Logger.Debugf("Error reading executable for process %d: %v", proc.Pid, err)
						break
					}
					if n == 0 {
						break
					}

					// Include overlap from the previous chunk
					if prevChunk != nil {
						copy(buffer[:overlapSize], prevChunk)
					}

					// Update the hash with the current chunk
					hasher.Write(buffer[:n+overlapSize])

					// Scan the chunk
					matches := PerformYaraScan(buffer[:n+overlapSize], compiledRules)

					// Output matches and log events
					if len(matches) == 0 {
						utils.Logger.Debugf("No YARA matches found for file %s", procExePath)
					} else {
						for _, match := range matches {
							if err := rule_utils.LogYaraDetection(match.Rule, exePath); err != nil {
								utils.Logger.Errorf("Error logging YARA detection for rule %s on file %s: %v", match.Rule, exePath, err)
							}

							// Quarantine the file if a match is found
							if err := QuarantineFile(exePath); err != nil {
								utils.Logger.Errorf("Failed to quarantine file %s: %v", exePath, err)
							}

							// Kill the process
							cmd := exec.Command("kill", "-9", fmt.Sprint(proc.Pid))
							if err := cmd.Run(); err != nil {
								utils.Logger.Errorf("Failed to kill process %d: %v", proc.Pid, err)
							} else {
								utils.Logger.Infof("Successfully killed process %d", proc.Pid)
							}
						}
					}

					// Store the last overlapSize bytes for the next chunk
					prevChunk = make([]byte, overlapSize)
					copy(prevChunk, buffer[n:n+overlapSize])

					// Check for timeout
					select {
					case <-time.After(5 * time.Second):
						utils.Logger.Debugf("YARA scan for process %d took too long, stopping scan", proc.Pid)
						break
					default:
					}
				}

				// Finalize the hash and check if it has been scanned
				hashStr := hex.EncodeToString(hasher.Sum(nil))
				if _, exists := scannedHashes[hashStr]; exists {
					utils.Logger.Debugf("Skipping process %d as it has been previously scanned and confirmed clean", proc.Pid)
					continue
				}

				// Add the hash to the scannedHashes map
				scannedHashes[hashStr] = struct{}{}
			}
		}
	}
}

// MonitorYARAFiles starts monitoring file events and triggers YARA scanning.
func MonitorYARAFiles(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Initialize YARA rules once
	if compiledRules == nil {
		compiledRules = InitializeYARARules()
		if compiledRules == nil {
			utils.Logger.Error("Failed to initialize YARA rules.")
			return
		}
	}

	watcher := GetWatcher()
	if watcher == nil {
		utils.Logger.Error("Watcher is not initialized.")
		return
	}

	for {
		select {
		case <-ctx.Done():
			// Handle cleanup and exit
			utils.Logger.Info("YARA Monitor shutting down...")
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				utils.Logger.Debugf("File modified or created: %s", event.Name)

				// Skip scanning if the file is in the /tmp/quarantine directory
				if strings.HasPrefix(event.Name, "/tmp/quarantine") {
					utils.Logger.Debugf("Skipping file in quarantine directory: %s", event.Name)
					continue
				}

				info, err := os.Stat(event.Name)
				if err == nil && info.IsDir() {
					// Add the new directory to the watcher
					if err := watcher.Add(event.Name); err != nil {
						utils.Logger.Errorf("Error watching new directory %s: %v", event.Name, err)
					} else {
						utils.Logger.Infof("Added new directory to watcher: %s", event.Name)
					}
				} else {
					RunYARARules(event.Name) // Use the pre-compiled rules
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			utils.Logger.Errorf("Watcher error: %v", err)
		}
	}
}

// isYARARuleFile checks if a file has a valid YARA rule file extension.
func isYARARuleFile(fileName string) bool {
	ext := filepath.Ext(fileName)
	return ext == ".yar" || ext == ".yara" // Handle both .yar and .yara extensions
}
