// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SeclangGenerator implements the Generator interface for seclang output
type SeclangGenerator struct{}

// NewSeclangGenerator creates a new seclang generator
func NewSeclangGenerator() *SeclangGenerator {
	return &SeclangGenerator{}
}

// Generate creates seclang output for a single rule
func (sg *SeclangGenerator) Generate(rule Rule) ([]byte, error) {
	// Convert a single rule back to seclang format
	seclangStr := rule.RawRule
	if seclangStr == "" {
		// If RawRule is not available, construct it from the parsed fields
		seclangStr = sg.constructSeclangFromRule(rule)
	}
	return []byte(seclangStr), nil
}

// GenerateFile creates seclang output for all rules in a file
func (sg *SeclangGenerator) GenerateFile(filePath string) ([]byte, error) {
	// Check if it's a YAML file (CRSLang format) or a .conf file
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		// Parse YAML file and convert to seclang
		return sg.generateFromYaml(filePath)
	}

	// Parse .conf file (seclang format)
	rules, err := ParseRuleFile(filePath)
	if err != nil {
		return nil, err
	}
	return sg.GenerateMultiple(rules)
}

// GenerateMultiple creates seclang output for multiple rules
func (sg *SeclangGenerator) GenerateMultiple(rules []Rule) ([]byte, error) {
	var result strings.Builder

	for _, rule := range rules {
		seclangStr, err := sg.Generate(rule)
		if err != nil {
			return nil, err
		}
		result.Write(seclangStr)
		result.WriteString("\n")
	}

	return []byte(result.String()), nil
}

// GetFileExtension returns the file extension for seclang files
func (sg *SeclangGenerator) GetFileExtension() string {
	return ".conf"
}

// GetOutputFileName generates the output filename for a given rule
func (sg *SeclangGenerator) GetOutputFileName(rule Rule) string {
	// Use the rule ID as the filename, similar to crslang's approach
	if rule.ID != "" {
		return fmt.Sprintf("rule-%s.conf", rule.ID)
	}
	return "rule.conf"
}

// constructSeclangFromRule constructs a seclang string from a parsed rule
func (sg *SeclangGenerator) constructSeclangFromRule(rule Rule) string {
	var seclang strings.Builder

	// Start with SecRule
	seclang.WriteString("SecRule ")

	// Add variables
	if len(rule.Variables) > 0 {
		var vars []string
		for _, v := range rule.Variables {
			if v.Exclude {
				vars = append(vars, "!"+v.Name)
			} else {
				vars = append(vars, v.Name)
			}
		}
		seclang.WriteString(strings.Join(vars, " "))
	} else {
		seclang.WriteString("ARGS") // Default variable
	}

	// Add operator
	seclang.WriteString(" \"@")
	seclang.WriteString(rule.Operator)
	seclang.WriteString("\" \\\n\t\"")

	// Build actions string
	var actions []string

	// Add ID
	if rule.ID != "" {
		actions = append(actions, "id:"+rule.ID)
	}

	// Add phase
	if rule.Phase != "" {
		actions = append(actions, "phase:"+rule.Phase)
	}

	// Add other actions from the map
	for action, value := range rule.Actions {
		if value != "" {
			actions = append(actions, action+":"+value)
		} else {
			actions = append(actions, action)
		}
	}

	// Add description if available
	if rule.Description != "" {
		actions = append(actions, "msg:'"+rule.Description+"'")
	}

	// Add logdata if available
	if rule.LogData != "" {
		actions = append(actions, "logdata:'"+rule.LogData+"'")
	}

	// Add tags if available
	if len(rule.Tags) > 0 {
		actions = append(actions, "tag:'"+strings.Join(rule.Tags, ",")+"'")
	}

	// Add other metadata
	if rule.Rev != "" {
		actions = append(actions, "rev:"+rule.Rev)
	}
	if rule.Ver != "" {
		actions = append(actions, "ver:"+rule.Ver)
	}
	if rule.Maturity != "" {
		actions = append(actions, "maturity:"+rule.Maturity)
	}
	if rule.Accuracy != "" {
		actions = append(actions, "accuracy:"+rule.Accuracy)
	}

	seclang.WriteString(strings.Join(actions, ",\\\n\t"))
	seclang.WriteString("\"")

	return seclang.String()
}

// generateFromYaml converts a CRSLang YAML file to seclang format
func (sg *SeclangGenerator) generateFromYaml(yamlFilePath string) ([]byte, error) {
	// Read the YAML file
	yamlData, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return nil, err
	}

	// Parse the YAML into our internal Rule structure
	var rule Rule
	if err := yaml.Unmarshal(yamlData, &rule); err != nil {
		return nil, err
	}

	// Convert to seclang format
	return sg.Generate(rule)
}
