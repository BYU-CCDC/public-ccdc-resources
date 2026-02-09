package snoopy_query

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Statement represents a single comparison statement
type Statement struct {
	Variable string
	Operator string
	Value    interface{} // Can be a string or []string
}

// Query represents the entire query, parsed into a series of statements
type Query struct {
	Statements   []Statement
	Conjunctions []string // "and" or "or"
}

// VarStore is our variable store, representing the JSON data
type VarStore map[string]interface{}

// ParseQuery parses a query string into a Query struct
func ParseQuery(queryString string) (Query, error) {
	var query Query
	parts := strings.Fields(queryString) // Simple whitespace-based splitting

	for i := 0; i < len(parts); { // Increment i within the loop
		if i+2 >= len(parts) {
			return Query{}, fmt.Errorf("incomplete statement at the end of query")
		}

		statement := Statement{
			Variable: parts[i],
			Operator: parts[i+1],
		}

		// Handle values (string, or list for 'in')
		if parts[i+1] == "in" {
			if i+2 >= len(parts) || !strings.HasPrefix(parts[i+2], "[") {
				return Query{}, fmt.Errorf("invalid 'in' list format")
			}

			// Find the closing bracket of the list
			endIndex := i + 3
			for ; endIndex < len(parts); endIndex++ {
				if strings.HasSuffix(parts[endIndex], "]") {
					break
				}
			}

			if endIndex == len(parts) {
				return Query{}, fmt.Errorf("unclosed 'in' list")
			}

			listStr := strings.Join(parts[i+2:endIndex+1], " ")
			listStr = strings.TrimPrefix(listStr, "[")
			listStr = strings.TrimSuffix(listStr, "]")
			items := strings.Split(listStr, ",")

			var cleanedItems []string
			for _, item := range items {
				cleanedItems = append(cleanedItems, strings.Trim(item, " \""))
			}

			statement.Value = cleanedItems
			i = endIndex + 1 // Adjust i to account for the processed list
		} else {
			valuePart := parts[i+2]
			if strings.HasPrefix(valuePart, "\"") && strings.HasSuffix(valuePart, "\"") {
				statement.Value = valuePart[1 : len(valuePart)-1] // Remove quotes
				i += 3                                            // increment to conjunction or end
			} else if valuePart == "and" || valuePart == "or" {
				return Query{}, fmt.Errorf("incomplete statement: missing value for '%s %s'", parts[i], parts[i+1])
			} else {
				statement.Value = valuePart
				i += 3 // increment to conjunction or end
			}
		}

		query.Statements = append(query.Statements, statement)

		// Add conjunctions if any
		if i < len(parts) {
			conjunction := parts[i]
			if conjunction != "and" && conjunction != "or" {
				return Query{}, fmt.Errorf("invalid conjunction: %s", conjunction)
			}
			query.Conjunctions = append(query.Conjunctions, conjunction)
			i++ // Move past conjunction
		}
	}

	return query, nil
}

// evaluateStatement evaluates a single statement against the VarStore
func EvaluateStatement(statement Statement, varStore VarStore) (bool, error) {
	value, err := GetVariableValue(varStore, statement.Variable)
	if err != nil {
		return false, err // Variable not found
	}

	switch statement.Operator {
	case "==":
		return EvaluateEquals(value, statement.Value), nil
	case "in":
		return EvaluateIn(value, statement.Value), nil
	case "like":
		return EvaluateLike(value, statement.Value), nil
	case ":":
		return EvaluateColon(value, statement.Value), nil
	default:
		return false, fmt.Errorf("unknown operator: %s", statement.Operator)
	}
}

// getVariableValue retrieves the value of a variable from the VarStore
func GetVariableValue(varStore VarStore, varPath string) (interface{}, error) {
	parts := strings.Split(varPath, ".")
	current := varStore
	for i, part := range parts {
		val, ok := current[part]
		if !ok {
			return nil, fmt.Errorf("variable not found: %s", varPath)
		}

		// If we reached the last part, return the value
		if i == len(parts)-1 {
			return val, nil
		}

		// Otherwise, expect the next level to be a map or array
		switch v := val.(type) {
		case map[string]interface{}:
			current = v
		case []interface{}:
			// If the next part is not the last, and the current part is an array,
			// we should return the array itself
			if i < len(parts)-1 {
				return val, nil
			}
			// If it's the last part and an array, return the array
			return val, nil
		default:
			return nil, fmt.Errorf("invalid path: %s", varPath)
		}
	}

	return nil, fmt.Errorf("invalid variable path: %s", varPath)
}

// evaluateIn checks if any element in value (if it's an array) is present in the list
func EvaluateIn(value interface{}, list interface{}) bool {
	strList, ok := list.([]string)
	if !ok {
		return false // Invalid list type
	}

	// Handle different types of value
	switch v := value.(type) {
	case []interface{}:
		for _, vv := range v {
			if EvaluateInSingleValue(vv, strList) {
				return true
			}
		}
	default:
		return EvaluateInSingleValue(v, strList)
	}

	return false
}

// evaluateInSingleValue checks if a single value is present in a list
func EvaluateInSingleValue(value interface{}, list []string) bool {
	strValue := fmt.Sprintf("%v", value)
	for _, item := range list {
		if strValue == item {
			return true
		}
	}
	return false
}

// evaluateLike performs a regex-based match using '*' as a wildcard
func EvaluateLike(value interface{}, pattern interface{}) bool {
	strPattern, ok := pattern.(string)
	if !ok {
		return false // Invalid pattern type
	}

	// Convert the wildcard pattern to a proper regex
	regexPattern := "^" + strings.ReplaceAll(strPattern, "*", ".*") + "$"

	// Handle different types of value
	switch v := value.(type) {
	case []interface{}:
		for _, item := range v {
			strValue := fmt.Sprintf("%v", item)
			matched, err := regexp.MatchString(regexPattern, strValue)
			if err != nil {
				return false // Invalid regex
			}
			if matched {
				return true
			}
		}
	default:
		strValue := fmt.Sprintf("%v", value)
		matched, err := regexp.MatchString(regexPattern, strValue)
		if err != nil {
			return false // Invalid regex
		}
		return matched
	}

	return false
}

func EvaluateEquals(value1, value2 interface{}) bool {
	// Convert both values to string for comparison
	strValue1 := fmt.Sprintf("%v", value1)
	strValue2 := fmt.Sprintf("%v", value2)
	return strValue1 == strValue2
}

// evaluateColon checks if any element in an array (value) matches the given string (strValue)
func EvaluateColon(value interface{}, match interface{}) bool {
	// Ensure the match value is a string
	strMatch, ok := match.(string)
	if !ok {
		return false // Invalid match type, should be a string
	}

	// Check if value is an array
	switch v := value.(type) {
	case []interface{}:
		for _, element := range v {
			// Convert element to string for comparison
			strElement := fmt.Sprintf("%v", element)
			if strElement == strMatch {
				return true // Found a match
			}
		}
	default:
		return false // value is not an array
	}

	return false // No match found
}

// EvaluateQuery evaluates the entire query against the VarStore
func EvaluateQuery(query Query, varStore VarStore) (bool, error) {
	if len(query.Statements) == 0 {
		return true, nil // Empty query is true
	}

	result, err := EvaluateStatement(query.Statements[0], varStore)
	if err != nil {
		return false, err
	}

	for i := 1; i < len(query.Statements); i++ {
		nextResult, err := EvaluateStatement(query.Statements[i], varStore)
		if err != nil {
			return false, err
		}

		conjunction := query.Conjunctions[i-1]
		if conjunction == "and" {
			result = result && nextResult
		} else { // "or"
			result = result || nextResult
		}
	}

	return result, nil
}

// CreateVarStoreFromJSON creates a VarStore from a JSON string
func CreateVarStoreFromJSON(jsonData string) (VarStore, error) {
	var varStore VarStore
	err := json.Unmarshal([]byte(jsonData), &varStore)
	if err != nil {
		return nil, err
	}
	return varStore, nil
}

func TestQueryLang() {
	// Sample JSON data
	jsonData := `
	{
		"process": {
			"name": "chrome",
			"pid": 1234,
			"args": ["--headless", "--remote-debugging-port=9222", "import subprocess call"]
		},
		"user": {
			"id": "123",
			"role": "user"
		},
		"event": {
			"type": "login",
			"location": "US",
			"timestamp": "2023-10-27T10:00:00Z"
		}
	}
	`

	// Create a VarStore from the JSON
	varStore, err := CreateVarStoreFromJSON(jsonData)
	if err != nil {
		fmt.Println("Error creating VarStore:", err)
		return
	}

	// Example queries
	queries := []string{
		"process.name == \"chrome\" and process.args in [\"--headless\", \"--remote-debugging-port=9222\"]",
		"user.id == \"123\" or user.role == \"admin\"",
		"process.args like \"*import*subprocess*call*\"",
		"event.type == \"login\" and event.location in [\"US\", \"CA\"] or event.timestamp like \"2023-10-27*\"",
		"process.name == \"chrome\" and process.pid == 1234", // Example with all fields in 'process'
		"process.args : \"--headless\"",
	}

	// Evaluate each query
	for _, queryString := range queries {
		query, err := ParseQuery(queryString)
		if err != nil {
			fmt.Printf("Error parsing query '%s': %s\n", queryString, err)
			continue
		}

		result, err := EvaluateQuery(query, varStore)
		if err != nil {
			fmt.Printf("Error evaluating query '%s': %s\n", queryString, err)
			continue
		}

		fmt.Printf("Query: %s\nResult: %t\n\n", queryString, result)
	}
}
