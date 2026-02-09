package rule_utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

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

func QuarantineFile(exePath string) {
	utils.Logger.Debug(fmt.Sprintf("Quarantining file %s", exePath))

	// Check if the exePath still exists
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		// File does not exist, no need to move
		return
	}

	// Ensure quarantine directory exists
	quarantineDir := "/tmp/quarantine"
	if _, err := os.Stat(quarantineDir); os.IsNotExist(err) {
		if err := os.MkdirAll(quarantineDir, 0750); err != nil {
			//utils.Logger.Error(fmt.Sprintf("Failed to create quarantine directory: %v", err))
			return
		}
	}

	// Generate destination path
	fileName := filepath.Base(exePath)
	destPath := filepath.Join(quarantineDir, fileName)

	// Check if the file is already quarantined
	if _, err := os.Stat(destPath); err == nil {
		// File already exists in quarantine, no need to move again
		return
	}

	// Remove execute permissions
	if err := os.Chmod(exePath, 0644); err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to remove execute permissions: %v", err))
		return
	}

	// Move file to quarantine directory
	if err := os.Rename(exePath, destPath); err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to move file to quarantine: %v", err))
		return
	}

	// Log success message
	utils.Logger.Info(fmt.Sprintf("Successfully quarantined file to %s", destPath))
}

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
