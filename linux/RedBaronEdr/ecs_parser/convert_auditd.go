package ecs_parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ConvertAuditToECS takes a generic map (parsed from an auditd-style event JSON)
// and converts it into an ECS JSON string, similar to the Python example.
func ConvertAuditToECS(inputData map[string]interface{}) (string, error) {
	// Safely get @timestamp or use current time if missing
	timestamp, ok := inputData["@timestamp"].(string)
	if !ok || timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Retrieve fields from the event.
	category, _ := getString(inputData, "category")
	outcome, _ := getString(inputData, "result")

	// Python code does: .get("ecs", {}).get("event", {}).get("type")
	// We'll replicate that pattern in Go:
	ecsMap := getMap(inputData, "ecs")
	ecsEventMap := getMap(ecsMap, "event")
	eventType, _ := getString(ecsEventMap, "type")

	// summary => for the "action"
	summaryMap := getMap(inputData, "summary")
	action, _ := getString(summaryMap, "action")

	// user => nested user fields
	userMap := getMap(inputData, "user")
	userIDs := getMap(userMap, "ids")
	userNames := getMap(userMap, "names")

	// process => parse the typical fields
	processMap := getMap(inputData, "process")
	processTitle, _ := getString(processMap, "title")
	// Python splits the `title` to get arguments (minus the first token).
	// We'll do that with strings.Fields, dropping the 0th element.
	procArgs := splitTitleToArgs(processTitle)

	// data => arch, syscall, etc.
	dataMap := getMap(inputData, "data")
	arch, _ := getString(dataMap, "arch")
	syscall, _ := getString(dataMap, "syscall")
	tty, _ := getString(dataMap, "tty")

	// Now gather everything into ECS fields.
	ecsData := map[string]interface{}{
		"@timestamp": timestamp,
		"event": map[string]interface{}{
			"category": category,
			"type":     eventType,
			"action":   action,
			"outcome":  outcome,
		},
		"user": map[string]interface{}{
			// IDs
			"id":   getStringOrNil(userIDs, "uid"),
			"name": getStringOrNil(userNames, "uid"),

			"target": map[string]interface{}{
				"id":   getStringOrNil(userIDs, "auid"),
				"name": getStringOrNil(userNames, "auid"),
			},
			"group": map[string]interface{}{
				"id":   getStringOrNil(userIDs, "gid"),
				"name": getStringOrNil(userNames, "gid"),
			},
			"effective": map[string]interface{}{
				"id":   getStringOrNil(userIDs, "euid"),
				"name": getStringOrNil(userNames, "euid"),
			},
			"selinux": getMap(userMap, "selinux"),
		},
		"process": map[string]interface{}{
			"name":       getStringOrNil(processMap, "name"),
			"pid":        getStringOrNil(processMap, "pid"),
			"ppid":       getStringOrNil(processMap, "ppid"),
			"title":      getStringOrNil(processMap, "title"),
			"executable": getStringOrNil(processMap, "exe"),
			"args":       procArgs,
			"arch":       arch,
			"syscall":    syscall,
			"tty": map[string]interface{}{
				"device": tty,
			},
		},
		// Also replicate "tags" and "summary" as in python code.
		"tags":    getArray(inputData, "tags"),
		"summary": summaryMap,
	}

	// (Optional) if you want to include a "process.parent.name" from a PPID lookup
	// define that logic here. e.g.:
	if ppid, ok := ecsData["process"].(map[string]interface{})["ppid"].(string); ok && ppid != "" {
		parentExecutable := lookupProcessNameByPID(ppid)
		parentName := getProcessBaseName(parentExecutable)
		ecsData["process"].(map[string]interface{})["parent"] = map[string]interface{}{
			"name":       parentName,
			"ppid":       ppid,
			"executable": parentExecutable,
		}
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(ecsData)
	if err != nil {
		return "", fmt.Errorf("error marshaling ECS data: %w", err)
	}
	return string(jsonBytes), nil
}

// lookupProcessNameByPID is a placeholder to retrieve the parent process name by PID.
// You can implement your own logic (e.g., read from /proc/<pid>/cmdline, or maintain
// a PID cache).
func lookupProcessNameByPID(ppid string) string {
	// Construct the path to the exe symlink for the given PID
	exePath := fmt.Sprintf("/proc/%s/exe", ppid)

	// Read the symbolic link to get the full path of the executable
	executablePath, err := os.Readlink(exePath)
	if err != nil {
		// If there's an error (e.g., process doesn't exist), return a default value
		return "unknown_process"
	}

	return executablePath
}

// getString is a helper to safely get a string from a map.
func getString(m map[string]interface{}, key string) (string, bool) {
	if val, ok := m[key]; ok {
		if s, ok2 := val.(string); ok2 {
			return s, true
		}
	}
	return "", false
}

// getStringOrNil tries to get a string from the map, else returns nil (for JSON marshalling).
func getStringOrNil(m map[string]interface{}, key string) interface{} {
	s, ok := getString(m, key)
	if !ok || s == "" {
		return nil
	}
	return s
}

// getMap is a helper to retrieve a sub-map (default to empty map if not found).
func getMap(m map[string]interface{}, key string) map[string]interface{} {
	val, ok := m[key]
	if !ok {
		return map[string]interface{}{}
	}
	if sub, ok := val.(map[string]interface{}); ok {
		return sub
	}
	return map[string]interface{}{}
}

// getArray is a helper to retrieve a slice (default to empty slice if not found).
func getArray(m map[string]interface{}, key string) []interface{} {
	val, ok := m[key]
	if !ok {
		return []interface{}{}
	}
	if arr, ok := val.([]interface{}); ok {
		return arr
	}
	return []interface{}{}
}

// splitTitleToArgs splits process.title into fields and discards the first element
// (replicating python's "title.split()[1:] if title else []" logic).
func splitTitleToArgs(title string) []string {
	if title == "" {
		return []string{}
	}
	fields := strings.Fields(title)
	if len(fields) <= 1 {
		return []string{}
	}
	// drop the first element
	return fields[1:]
}
