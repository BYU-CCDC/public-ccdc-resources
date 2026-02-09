package ecs_parser

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ConvertKubeArmorLog(inputData map[string]interface{}) (string, error) {
	// Create ECS data structure
	ecsData := map[string]interface{}{
		"@timestamp": inputData["UpdatedTime"],
		"host": map[string]interface{}{
			"name": inputData["HostName"],
			"id":   fmt.Sprintf("%v", inputData["UID"]),
			"os": map[string]interface{}{
				"platform": "linux",
				"type":     "linux",
			},
		},
		"process": map[string]interface{}{
			"name":              getProcessBaseName(fmt.Sprintf("%v", inputData["ProcessName"])),
			"pid":               inputData["PID"],
			"ppid":              inputData["PPID"],
			"args":              splitResource(fmt.Sprintf("%v", inputData["Resource"])),
			"executable":        inputData["ProcessName"],
			"working_directory": inputData["Cwd"],
			"tty": map[string]interface{}{
				"device": inputData["TTY"],
			},
			"parent": map[string]interface{}{
				"name":       getProcessBaseName(fmt.Sprintf("%v", inputData["ParentProcessName"])),
				"pid":        inputData["HostPPID"],
				"executable": inputData["ParentProcessName"],
			},
		},
		"event": map[string]interface{}{
			"kind":     "event",
			"category": []string{"process"},
			"type":     "start",
			"action": func() string {
				if fmt.Sprintf("%v", inputData["Data"]) == "syscall=SYS_EXECVE" {
					return "exec"
				}
				return fmt.Sprintf("%v", inputData["Data"])
			}(),
			"outcome": getOutcome(fmt.Sprintf("%v", inputData["Result"])),
		},
		"user": map[string]interface{}{
			"id": fmt.Sprintf("%v", inputData["UID"]),
		},
	}

	// Convert to JSON string
	jsonBytes, err := json.Marshal(ecsData)
	if err != nil {
		return "", fmt.Errorf("error marshaling ECS data: %v", err)
	}

	return string(jsonBytes), nil
}

// Helper function to split Resource string into args
func splitResource(resource string) []string {
	if resource == "" {
		return []string{}
	}
	return strings.Fields(resource)
}

// Helper function to convert Result to outcome
func getOutcome(result string) string {
	if result == "Passed" {
		return "success"
	}
	return "failure"
}

func getProcessBaseName(processName string) string {
	parts := strings.Split(processName, "/")
	return parts[len(parts)-1]
}
