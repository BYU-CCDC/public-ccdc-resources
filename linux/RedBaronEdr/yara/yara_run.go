package yara

import (
	"os"
	"strings"

	"red-baron-edr/rule_engine2/rule_utils"

	"red-baron-edr/utils"

	"github.com/hillu/go-yara/v4"
)

const TypeDetectedEvent = "event:detected"

// RunYARARules processes a file using pre-compiled YARA rules and logs detected events.
func RunYARARules(filePath string) {
	if compiledRules == nil {
		utils.Logger.Fatalf("YARA rules have not been initialized.")
		return
	}

	// Skip scanning if the file is in the excluded directory
	if strings.HasPrefix(filePath, "/etc/redbaron/yara_rules") {
		utils.Logger.Debugf("Skipping YARA rules file: %s", filePath)
		return
	}

	// Read file content to scan
	data, err := os.ReadFile(filePath)
	if err != nil {
		utils.Logger.Debugf("Error reading file %s: %v", filePath, err)
		return
	}

	// Perform YARA scan using the pre-compiled rules
	matches := PerformYaraScan(data, compiledRules)

	// Output matches and log events
	if len(matches) == 0 {
		utils.Logger.Debugf("No YARA matches found for file %s", filePath)
	} else {
		for _, match := range matches {
			rule_utils.LogYaraDetection(match.Rule, filePath)

			// Quarantine the file if a match is found
			//	Quarantine is in run MonitorYARAFiles then ScanProcesses, so the file can get deleted before this
			if _, err := os.Stat(filePath); err == nil {
				if err := rule_utils.QuarantineFile(filePath); err != nil {
					utils.Logger.Errorf("Failed to quarantine file %s: %v", filePath, err)
				}
			}
		}
	}
}

// PerformYaraScan scans a byte array with YARA rules and returns the matches.
func PerformYaraScan(data []byte, rules *yara.Rules) yara.MatchRules {
	var matches yara.MatchRules
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		utils.Logger.Fatalf("Error creating YARA scanner:", err)
		return matches
	}

	err = scanner.SetCallback(&matches).ScanMem(data)
	if err != nil {
		utils.Logger.Errorf("Error scanning data with YARA rules:", err)
	}
	return matches
}
