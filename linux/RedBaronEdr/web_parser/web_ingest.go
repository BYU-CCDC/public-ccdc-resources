package web_parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"red-baron-edr/rule_engine2/rule_utils"
	"red-baron-edr/utils"
)

func StartWebScan() {
	utils.Logger.Debug("Started Web Monitor")

	logFiles := []string{
		"/var/log/nginx/access.log",
		"/usr/local/nginx/logs/access.log",
		"/var/log/httpd/access.log",
		"/var/nginx/logs/access.log",
		"/opt/nginx/logs/access.log",
		"/var/log/httpd/access_log",
		"/var/log/apache2/access.log",
		"/usr/local/apache2/logs/access_log",
		"/opt/apache/logs/access.log",
	}

	for {
		for _, logFile := range logFiles {
			processLogFile(logFile)
		}
		time.Sleep(5 * time.Second) // Scan logs every 5 seconds
	}
}

func processLogFile(logFile string) {
	offsetFile := logFile + ".offset"
	offset := readOffset(offsetFile)

	// Define regex patterns for specific malicious patterns
	maliciousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\.\./\.\./\.\./`),
		regexp.MustCompile(`%2E%2E%2F%2E%2E%2F%2E%2E%2F`),
	}

	// Load patterns for user-agent and URI
	userAgentPatterns := loadPatternsFromFiles([]string{fmt.Sprintf("%s/scanners-user-agents.data", utils.WebRulesDir)})
	uriPatterns := loadPatternsFromFiles([]string{
		fmt.Sprintf("%s/lfi-os-files.data", utils.WebRulesDir),
		fmt.Sprintf("%s/unix-shell.data", utils.WebRulesDir),
	})

	file, err := os.Open(logFile)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	utils.Logger.Debug("Processing log file:", logFile)

	// Skip lines up to the offset
	for i := 0; i < offset && scanner.Scan(); i++ {
	}

	linesProcessed := 0
	for scanner.Scan() {
		line := scanner.Text()
		ip := extractIP(line)
		if ip == "" || ip == "127.0.0.1" {
			utils.Logger.Debug("Skipping line with invalid IP:", line)
			continue
		}

		method, uri, _ := extractURI(line)
		if uri == "" {
			utils.Logger.Debug("Skipping line with invalid URI:", line)
			continue
		}

		utils.Logger.Debug(fmt.Sprintf("Method: %s, URI: %s", method, uri))

		_, userAgent := extractHeaders(line)

		// Check for malicious patterns in the URI using regex
		for _, pattern := range maliciousPatterns {
			if pattern.MatchString(uri) {
				utils.Logger.Debug(fmt.Sprintf("Malicious pattern detected in URI for IP: %s", ip))
				rule_utils.LogPatternDetection(ip, uri)
				// Implement logic to handle detected malicious activity
			}
		}

		// Check for user-agent patterns
		for _, pattern := range userAgentPatterns {
			if pattern.MatchString(userAgent) {
				utils.Logger.Debug(fmt.Sprintf("Malicious pattern detected in User-Agent for IP: %s", ip))
				rule_utils.LogPatternDetection(ip, uri)
				// Implement logic to handle detected malicious activity
			}
		}

		// Check for URI patterns
		for _, pattern := range uriPatterns {
			if strings.Contains(uri, pattern.String()) {
				utils.Logger.Debug(fmt.Sprintf("Malicious Pattern detected in URI for IP: %s", ip))
				rule_utils.LogPatternDetection(ip, uri)
				// Implement logic to handle detected activity
			}
		}

		linesProcessed++
	}

	if err := scanner.Err(); err != nil {
		utils.Logger.Debug(fmt.Sprintf("Error reading log file: %s", logFile))
	}

	utils.Logger.Debug(fmt.Sprintf("Processed %d lines from log file: %s", linesProcessed, logFile))
	writeOffset(offsetFile, offset+linesProcessed)
}

func extractIP(logLine string) string {
	// Regular expression to match IPv4 addresses
	ipRegex := `(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)`
	re := regexp.MustCompile(ipRegex)

	// Find the first match of the IP address in the log line
	firstMatch := re.FindString(logLine)
	return firstMatch
}

// func nullRouteIP(ip string) {
// 	utils.Logger.Debug(fmt.Sprintf("Null-routing IP address: %s", ip))
// 	// Implement logic to null route the IP address
// }

func readOffset(offsetFile string) int {
	file, err := os.Open(offsetFile)
	if err != nil {
		return 0 // Start from the beginning if the offset file doesn't exist
	}
	defer file.Close()

	var offset int
	_, err = fmt.Fscanf(file, "%d", &offset)
	if err != nil {
		return 0
	}
	return offset
}

func writeOffset(offsetFile string, offset int) {
	file, err := os.Create(offsetFile)
	if err != nil {
		utils.Logger.Debug(fmt.Sprintf("Failed to write offset file: %s", offsetFile))
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "%d", offset)
}

// Function to extract URI, method, and protocol from a log line
func extractURI(logLine string) (string, string, string) {
	// Regular expression to match the HTTP method, URI, and protocol
	uriRegex := `"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^ ]+) (HTTP/\d\.\d)"`
	re := regexp.MustCompile(uriRegex)

	// Find the first match of the URI in the log line
	matches := re.FindStringSubmatch(logLine)
	if len(matches) < 4 {
		return "", "", ""
	}

	method := matches[1]
	uri := matches[2]
	protocol := matches[3]

	return method, uri, protocol
}

// Function to extract headers from a log line
func extractHeaders(logLine string) (string, string) {
	// Example regex to extract Host and User-Agent from the log line
	hostRegex := `"(http[s]?://[^"]+)"`
	userAgentRegex := `"([^"]+)"$`

	hostRe := regexp.MustCompile(hostRegex)
	userAgentRe := regexp.MustCompile(userAgentRegex)

	hostMatch := hostRe.FindStringSubmatch(logLine)
	userAgentMatch := userAgentRe.FindStringSubmatch(logLine)

	host := ""
	if len(hostMatch) > 1 {
		host = hostMatch[1]
	}

	userAgent := ""
	if len(userAgentMatch) > 1 {
		userAgent = userAgentMatch[1]
	}

	return host, userAgent
}

// Function to load patterns from multiple files
func loadPatternsFromFiles(filePaths []string) []*regexp.Regexp {
	var patterns []*regexp.Regexp

	for _, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err != nil {
			utils.Logger.Debug(fmt.Sprintf("Failed to open patterns file: %s", filePath))
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			pattern := scanner.Text()
			if pattern != "" {
				patterns = append(patterns, regexp.MustCompile(regexp.QuoteMeta(pattern)))
			}
		}

		if err := scanner.Err(); err != nil {
			utils.Logger.Debug(fmt.Sprintf("Error reading patterns file: %s", filePath))
		}
	}

	return patterns
}
