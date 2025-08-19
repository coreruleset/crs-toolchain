// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// YAMLGenerator implements the experimental.Generator interface for YAML output
type YAMLGenerator struct{}

// NewYAMLGenerator creates a new YAML generator
func NewYAMLGenerator() *YAMLGenerator {
	return &YAMLGenerator{}
}

// Generate creates YAML output for a single rule
func (yg *YAMLGenerator) Generate(rule Rule) ([]byte, error) {
	return yaml.Marshal(rule)
}

// GenerateFile creates YAML output for all rules in a file
func (yg *YAMLGenerator) GenerateFile(filePath string) ([]byte, error) {
	rules, err := ParseRuleFile(filePath)
	if err != nil {
		return nil, err
	}
	return yg.GenerateMultiple(rules)
}

// GenerateMultiple creates YAML output for multiple rules
func (yg *YAMLGenerator) GenerateMultiple(rules []Rule) ([]byte, error) {
	// Follow the crslang pattern: create a ConfigurationList structure
	if len(rules) == 0 {
		return yaml.Marshal(ConfigurationList{})
	}

	// Group rules by their ID prefix (first 3 characters)
	ruleGroups := make(map[string][]Rule)
	for _, rule := range rules {
		prefix := rule.ID[:3] // Get first 3 characters of ID
		ruleGroups[prefix] = append(ruleGroups[prefix], rule)
	}

	// Create DirectiveList for each group
	var directiveLists []DirectiveList
	for prefix, groupRules := range ruleGroups {
		directiveList := DirectiveList{
			ID:         prefix,
			Directives: groupRules,
		}
		directiveLists = append(directiveLists, directiveList)
	}

	configList := ConfigurationList{
		DirectiveList: directiveLists,
	}

	return yaml.Marshal(configList.DirectiveList)
}

// GetFileExtension returns the file extension for YAML files
func (yg *YAMLGenerator) GetFileExtension() string {
	return ".yaml"
}

// GetOutputFileName generates the output filename for a given rule
func (yg *YAMLGenerator) GetOutputFileName(rule Rule) string {
	return fmt.Sprintf("rule-%s.yaml", rule.ID)
}
