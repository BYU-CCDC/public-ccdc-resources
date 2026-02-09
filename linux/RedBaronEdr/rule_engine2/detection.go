package rule_engine2

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"red-baron-edr/rule_engine2/rule_utils"
	"red-baron-edr/snoopy_query"
	"red-baron-edr/utils"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/BurntSushi/toml"
)

// Rule represents the structure of our TOML rule files
type Rule struct {
	Rule struct {
		Description string   `toml:"description"`
		ID          string   `toml:"id"`
		License     string   `toml:"license"`
		Name        string   `toml:"name"`
		OSList      []string `toml:"os_list"`
		Version     string   `toml:"version"`
		Query       string   `toml:"query"`
	} `toml:"rule"`
	Actions []struct {
		Action string `toml:"action"`
		Field  string `toml:"field"`
	} `toml:"actions"`
}

var loadedRules []Rule
var rulesInitialized bool
var ruleMutex sync.RWMutex

func init() {
	// Initialize rules when the package is first loaded
	if err := Initialize(); err != nil {
		utils.Logger.Errorf("Failed to initialize rules: %v", err)
	}
}

// Initialize loads all TOML rules from the rulesV2 directory
func Initialize() error {
	ruleMutex.Lock()
	defer ruleMutex.Unlock()

	// Skip if rules are already initialized
	if rulesInitialized {
		return nil
	}

	files, err := os.ReadDir(utils.RulesV2Dir)
	if err != nil {
		return fmt.Errorf("failed to read rules directory: %v", err)
	}

	loadedRules = make([]Rule, 0) // Clear existing rules
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".toml" {
			var rule Rule
			path := filepath.Join(utils.RulesV2Dir, file.Name())

			if _, err := toml.DecodeFile(path, &rule); err != nil {
				utils.Logger.Errorf("Failed to decode rule file %s: %v", file.Name(), err)
				continue
			}

			loadedRules = append(loadedRules, rule)
			utils.Logger.Infof("Loaded rule: %s", rule.Rule.Name)
		}
	}

	rulesInitialized = true
	return nil
}

// IngestDetection processes an event against all loaded rules
func IngestDetection(ecsData []interface{}) (bool, string) {
	ruleMutex.RLock()
	defer ruleMutex.RUnlock()

	if len(ecsData) == 0 {
		return false, ""
	}

	// Convert the first element to JSON for query evaluation
	jsonBytes, err := json.Marshal(ecsData[0])
	if err != nil {
		utils.Logger.Errorf("Failed to marshal ECS data: %v", err)
		return false, ""
	}

	// Create VarStore from JSON
	varStore, err := snoopy_query.CreateVarStoreFromJSON(string(jsonBytes))
	if err != nil {
		utils.Logger.Errorf("Failed to create VarStore: %v", err)
		return false, ""
	}

	// Check each rule
	for _, rule := range loadedRules {
		// Parse and evaluate the query

		// Strip newlines from query before parsing
		queryStr := strings.ReplaceAll(rule.Rule.Query, "\n", " ")
		utils.Logger.Debugf("Parsing query: %v", queryStr)
		query, err := snoopy_query.ParseQuery(queryStr)
		utils.Logger.Debugf("Parsed query: %v", query)
		if err != nil {
			utils.Logger.Errorf("Failed to parse rule query '%s': %v", queryStr, err)
			continue
		}

		matched, err := snoopy_query.EvaluateQuery(query, varStore)
		if err != nil {
			utils.Logger.Errorf("Failed to evaluate query: %v", err)
			continue
		}

		if matched {
			utils.Logger.Infof("Rule matched: %s", rule.Rule.Name)

			// Log the detection
			rule_utils.LogRuleDetection("kuebarmor", ecsData, rule.Rule.Name)

			return true, rule.Rule.ID
		}
	}

	return false, ""
}

// HandleDetection executes the actions specified in the matched rule
func HandleDetection(ruleID string, ecsData map[string]interface{}) error {
	var matchedRule Rule

	// Find the matching rule
	for _, rule := range loadedRules {
		if rule.Rule.ID == ruleID {
			matchedRule = rule
			break
		}
	}

	if matchedRule.Rule.ID == "" {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	// Execute each action in the rule
	for _, action := range matchedRule.Actions {
		switch action.Action {
		case "kill_process":
			// Extract PID from the specified field
			pidInterface := getNestedValue(ecsData, strings.Split(action.Field, "."))
			if pidInterface == nil {
				return fmt.Errorf("field %s not found in event data", action.Field)
			}

			// Convert PID to int
			var pid int
			switch v := pidInterface.(type) {
			case float64:
				pid = int(v)
			case string:
				pid, _ = strconv.Atoi(v)
			case int:
				pid = v
			default:
				return fmt.Errorf("invalid PID format")
			}

			// Kill the process
			if err := killProcess(pid); err != nil {
				return fmt.Errorf("failed to kill process %d: %v", pid, err)
			}
			utils.Logger.Infof("Killed process %d", pid)

		// Add more action types here as needed
		default:
			return fmt.Errorf("unsupported action: %s", action.Action)
		}
	}

	return nil
}

// Helper function to get nested value from map using dot notation
func getNestedValue(data map[string]interface{}, keys []string) interface{} {
	current := data
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

// killProcess terminates a process by PID
func killProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGKILL)
}
