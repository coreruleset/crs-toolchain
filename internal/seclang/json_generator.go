// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"encoding/json"
	"fmt"
)

// JSONGenerator implements the Generator interface for JSON output
type JSONGenerator struct{}

// NewJSONGenerator creates a new JSON generator
func NewJSONGenerator() *JSONGenerator {
	return &JSONGenerator{}
}

// Generate creates JSON output for a single rule (legacy, kept for backward compatibility)
func (jg *JSONGenerator) Generate(rule Rule) ([]byte, error) {
	return json.MarshalIndent(rule, "", "  ")
}

// GenerateFile creates JSON output for all rules in a file
func (jg *JSONGenerator) GenerateFile(filePath string) ([]byte, error) {
	directiveList, err := ParseRuleFileToDirectiveList(filePath)
	if err != nil {
		return nil, err
	}
	return jg.GenerateDirectiveList(directiveList)
}

// GenerateDirectiveList creates JSON output for a DirectiveList
func (jg *JSONGenerator) GenerateDirectiveList(directiveList *DirectiveList) ([]byte, error) {
	return json.MarshalIndent(directiveList, "", "  ")
}

// GenerateMultiple creates JSON output for multiple rules (legacy, kept for backward compatibility)
func (jg *JSONGenerator) GenerateMultiple(rules []Rule) ([]byte, error) {
	// Create a wrapper structure for the JSON output
	output := struct {
		Rules []Rule `json:"rules"`
	}{
		Rules: rules,
	}
	return json.MarshalIndent(output, "", "  ")
}

// GetFileExtension returns the file extension for JSON files
func (jg *JSONGenerator) GetFileExtension() string {
	return ".json"
}

// GetOutputFileName generates the output filename for a given rule
func (jg *JSONGenerator) GetOutputFileName(rule Rule) string {
	return fmt.Sprintf("rule-%s.json", rule.ID)
}
