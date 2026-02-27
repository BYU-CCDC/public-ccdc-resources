package rule_utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"io"
	"os/exec"

	"red-baron-edr/utils"
)

func LogPatternDetection(ip string, uri string) {
	// Get current timestamp in RFC3339 format
	timestamp := time.Now().Format(time.RFC3339)

	detection := map[string]interface{}{
		"timestamp": timestamp,
		"type":      "pattern_detection",
		"ip":        ip,
		"uri":       uri,
	}

	// Convert map to JSON string
	jsonStr, err := json.Marshal(detection)
	if err != nil {
		log.Printf("Error marshaling detection: %v", err)
		return
	}

	// Append to detections log file
	logFilePath := filepath.Join(utils.LogDir, "detections.log")

	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening detections log: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(string(jsonStr) + "\n"); err != nil {
		log.Printf("Error writing to detections log: %v", err)
	}
}

func LogYaraDetection(rule string, exePath string) error {
	// Get current timestamp in RFC3339 format
	timestamp := time.Now().Format(time.RFC3339)

	detection := map[string]interface{}{
		"timestamp": timestamp,
		"type":      "yara_detection",
		"rule":      rule,
		"file_path": exePath,
	}

	// Convert map to JSON string
	jsonStr, err := json.Marshal(detection)
	if err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error marshaling detection: %v", err))
		return fmt.Errorf("error marshaling detection: %v", err)
	}

	// Append to detections log file in /var/log/redbaronedr/
	logFilePath := filepath.Join(utils.LogDir, "detections.log")
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error opening detections log: %v", err))
		return fmt.Errorf("error opening detections log: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(string(jsonStr) + "\n"); err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error writing to detections log: %v", err))
		return fmt.Errorf("error writing to detections log: %v", err)
	}

	return nil
}

// This function's error will be handled in the caller
func MoveFile(srcPath string, destPath string) error {
	// Try simple rename first
	err := os.Rename(srcPath, destPath)
	if err == nil {
		return nil
	}

	// If it's not a cross-device error, return it
	linkErr, ok := err.(*os.LinkError)
	if !ok {
		return err
	}

	// This means that /tmp is mounted as a tmpfs and os.Rename fails
	if linkErr.Err.Error() != "invalid cross-device link" {
		return err
	}

	// If we can't rename, it has to copy and then remove the original file
	sourceFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// makes sure the transfer buffer is cleared (synced)
	if err := destFile.Sync(); err != nil {
		return err
	}

	if err := sourceFile.Close(); err != nil {
		return err
	}

	if err := os.Remove(srcPath); err != nil {
		return err
	}

	return nil
}

// func QuarantineFile(exePath string) {
// 	utils.Logger.Debug(fmt.Sprintf("Quarantining file %s", exePath))

// 	// Check if the exePath still exists
// 	if _, err := os.Stat(exePath); os.IsNotExist(err) {
// 		// File does not exist, no need to move
// 		return
// 	}

// 	// Ensure quarantine directory exists
// 	quarantineDir := "/tmp/quarantine"
// 	if _, err := os.Stat(quarantineDir); os.IsNotExist(err) {
// 		if err := os.MkdirAll(quarantineDir, 0750); err != nil {
// 			//utils.Logger.Error(fmt.Sprintf("Failed to create quarantine directory: %v", err))
// 			return
// 		}
// 	}

// 	// Generate destination path
// 	fileName := filepath.Base(exePath)
// 	destPath := filepath.Join(quarantineDir, fileName)

// 	// Check if the file is already quarantined
// 	if _, err := os.Stat(destPath); err == nil {
// 		// File already exists in quarantine, no need to move again
// 		return
// 	}

// 	// Remove execute permissions
// 	if err := os.Chmod(exePath, 0644); err != nil {
// 		utils.Logger.Error(fmt.Sprintf("Failed to remove execute permissions: %v", err))
// 		return
// 	}

// 	// Move file to quarantine directory
// 	if err := os.Rename(exePath, destPath); err != nil {
// 		utils.Logger.Error(fmt.Sprintf("Failed to move file to quarantine: %v", err))
// 		return
// 	}

// 	// Log success message
// 	utils.Logger.Info(fmt.Sprintf("Successfully quarantined file to %s", destPath))
// }

// QuarantineFile moves the file to a quarantine directory and modifies its header.
func QuarantineFile(filePath string) error {
	quarantineDir := "/tmp/quarantine"

	// Create the quarantine directory if it doesn't exist
	if err := os.MkdirAll(quarantineDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %v", err)
	}

	// Move the file to the quarantine directory
	destPath := filepath.Join(quarantineDir, filepath.Base(filePath))
	// if err := os.Rename(filePath, destPath); err != nil {
	// 	return fmt.Errorf("failed to move file to quarantine: %v", err)
	// }

	if err := MoveFile(filePath, destPath); err != nil {
		return fmt.Errorf("Failed to move file to quarantine: %v", err)
	}

	// Use sed to remove the binary header
	cmd := exec.Command("sed", "-i", "1s/.*/REMOVED_HEADER/", destPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to modify file header: %v", err)
	}

	return nil
}
// this function was in both files? not sure why, but we're moving the good version 
//     here and fixing MoveFile

func LogRuleDetection(source string, ecsData []interface{}, ruleName string) {
	// Get current timestamp in RFC3339 format
	timestamp := time.Now().Format(time.RFC3339)

	// Extract process name and parent process from ecsData
	processName := getNestedValue(ecsData, []string{"process", "name"})
	parentProcess := getNestedValue(ecsData, []string{"process", "parent", "name"})

	detection := map[string]interface{}{
		"timestamp":      timestamp,
		"type":           "rule_detection",
		"source":         source,
		"process_name":   processName,
		"parent_process": parentProcess,
		"rule_name":      ruleName,
	}

	// Convert map to JSON string
	jsonStr, err := json.Marshal(detection)
	if err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error marshaling detection: %v", err))
		return
	}

	// Append to detections log file
	logFilePath := filepath.Join(utils.LogDir, "detections.log")
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error opening detections log: %v", err))
		return
	}
	defer f.Close()

	if _, err := f.WriteString(string(jsonStr) + "\n"); err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error writing to detections log: %v", err))
	}
}

// Helper function to get nested value from map using dot notation
func getNestedValue(data []interface{}, keys []string) interface{} {
	if len(data) == 0 {
		return nil
	}
	current, ok := data[0].(map[string]interface{})
	if !ok {
		return nil
	}
	for i, key := range keys {
		if i == len(keys)-1 {
			return current[key]
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}
	return nil
}
