package kubearmor_provider

import (
	"encoding/json"
	"os"
	"red-baron-edr/ecs_parser"
	"red-baron-edr/kubearmor_provider/client"
	"red-baron-edr/rule_engine2"
	"red-baron-edr/utils"

	"sync"
)

// ProcessJSONLog Function
func ProcessJSONLog(jsonData string) {

	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &logEntry); err != nil {
		utils.Logger.Errorf("Failed to unmarshal JSON log: %s\n", err)
		return
	}

	// Convert the log entry to ECS format
	ecsJSON, err := ecs_parser.ConvertKubeArmorLog(logEntry)
	if err != nil {
		utils.Logger.Errorf("Failed to convert log to ECS format: %s\n", err)
		return
	}

	utils.Logger.Debugf("ECS JSON: %v\n", ecsJSON)
	// Convert ecsJSON string to map[string]interface{}
	var ecsData map[string]interface{}
	if err := json.Unmarshal([]byte(ecsJSON), &ecsData); err != nil {
		utils.Logger.Errorf("Failed to unmarshal ECS JSON: %s\n", err)
		return
	}

	// Check against rule engine
	ecsDataSlice := []interface{}{ecsData}
	if matched, ruleID := rule_engine2.IngestDetection(ecsDataSlice); matched {
		utils.Logger.Info("Rule matched for JSON log")

		// Call HandleDetection from kill_engine
		if err := rule_engine2.HandleDetection(ruleID, ecsData); err != nil {
			utils.Logger.Errorf("Failed to handle detection: %s\n", err)
		}
	}

	// If debug mode is enabled, log ECS events to a file
	if utils.DebugMode {
		file, err := os.OpenFile("/var/log/ecs.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			utils.Logger.Errorf("Failed to open ECS log file: %s\n", err)
			return
		}
		defer file.Close()

		ecsJSONBytes, err := json.Marshal(ecsData)
		if err != nil {
			utils.Logger.Errorf("Failed to marshal ECS data: %s\n", err)
			return
		}

		if _, err := file.Write(append(ecsJSONBytes, '\n')); err != nil {
			utils.Logger.Errorf("Failed to write ECS data to file: %s\n", err)
		}
	}

	// Process the log entry as needed
	// utils.Logger.Fatalf("Processed JSON log: %v\n", ecsJSON)
}

// StartKAIngestor Function
func StartKAIngestor() {
	// Initialize rules before starting
	if err := rule_engine2.Initialize(); err != nil {
		utils.Logger.Fatalf("Failed to initialize rules: %v", err)
		return
	}
	utils.Logger.Info("Rules initialized successfully")

	server := os.Getenv("KUBEARMOR_SERVICE")
	if server == "" {
		server = "localhost:32767"
	}

	// Initialize client
	logClient := client.NewClient(server)
	if logClient == nil {
		utils.Logger.Fatalf("Failed to connect to the gRPC server (%s)\n", server)
		return
	}
	defer logClient.DestroyClient()

	// Perform health check
	if !logClient.DoHealthCheck() {
		utils.Logger.Errorf("Failed to perform health check on the gRPC server")
		return
	}

	// Start watching logs
	logChan := logClient.WatchLogs(true)
	utils.Logger.Info("Started Listening for KubeArmor Logs via GRPC...")

	// Use a WaitGroup to ensure the goroutine finishes before exiting
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for log := range logChan {
			ProcessJSONLog(log)
		}
	}()

	// Wait for the goroutine to finish (or add additional logic to prevent premature return)
	wg.Wait()
}
