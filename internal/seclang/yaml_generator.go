// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLGenerator implements the experimental.Generator interface for YAML output
type YAMLGenerator struct{}

// NewYAMLGenerator creates a new YAML generator
func NewYAMLGenerator() *YAMLGenerator {
	return &YAMLGenerator{}
}

// Generate creates YAML output for a single rule (legacy, kept for backward compatibility)
func (yg *YAMLGenerator) Generate(rule Rule) ([]byte, error) {
	return yaml.Marshal(rule)
}

// GenerateFile creates YAML output for all rules in a file
func (yg *YAMLGenerator) GenerateFile(filePath string) ([]byte, error) {
	directiveList, err := ParseRuleFileToDirectiveList(filePath)
	if err != nil {
		return nil, err
	}
	// Filter out administrative rules
	directiveList = yg.filterAdministrativeRules(directiveList)
	return yg.GenerateDirectiveList(directiveList)
}

// GenerateDirectiveList creates YAML output for a DirectiveList
func (yg *YAMLGenerator) GenerateDirectiveList(directiveList *DirectiveList) ([]byte, error) {
	return yaml.Marshal(directiveList)
}

// GenerateMultiple creates YAML output for multiple rules (legacy, kept for backward compatibility)
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
		// Convert legacy Rule to SeclangDirective (using a simple wrapper)
		var directives []SeclangDirective
		for _, rule := range groupRules {
			// For legacy compatibility, we'll create a simple wrapper
			// This is not ideal but maintains backward compatibility
			directives = append(directives, &legacyRuleWrapper{rule})
		}
		
		directiveList := DirectiveList{
			ID:         prefix,
			Directives: directives,
		}
		directiveLists = append(directiveLists, directiveList)
	}

	configList := ConfigurationList{
		DirectiveList: directiveLists,
	}

	return yaml.Marshal(configList.DirectiveList)
}

// legacyRuleWrapper is a wrapper to make legacy Rule compatible with SeclangDirective interface
type legacyRuleWrapper struct {
	Rule Rule
}

func (lrw *legacyRuleWrapper) ToSeclang() string {
	return lrw.Rule.RawRule
}

// GenerateFromDirectory creates YAML output for all .conf files in a directory
func (yg *YAMLGenerator) GenerateFromDirectory(dirPath string) ([]byte, error) {
	var allDirectiveLists []DirectiveList

	// Walk through the directory to find .conf files
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			directiveList, err := ParseRuleFileToDirectiveList(path)
			if err != nil {
				return err
			}
			// Filter out administrative rules
			directiveList = yg.filterAdministrativeRules(directiveList)
			allDirectiveLists = append(allDirectiveLists, *directiveList)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	configList := ConfigurationList{
		DirectiveList: allDirectiveLists,
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

// filterAdministrativeRules filters out administrative rules from a DirectiveList
// Administrative rules are those with IDs ending in 1-8
func (yg *YAMLGenerator) filterAdministrativeRules(directiveList *DirectiveList) *DirectiveList {
	if directiveList == nil {
		return directiveList
	}

	var filteredDirectives []SeclangDirective
	for _, directive := range directiveList.Directives {
		// Check if this directive is a rule with an ID
		if ruleWithCondition, ok := directive.(*RuleWithCondition); ok {
			// Skip administrative rules (IDs ending in 1-8)
			if isAdministrativeRule(ruleWithCondition.Metadata.Id) {
				continue
			}
		}
		// Keep all other directives (comments, configuration, etc.)
		filteredDirectives = append(filteredDirectives, directive)
	}

	return &DirectiveList{
		ID:         directiveList.ID,
		Directives: filteredDirectives,
		Marker:     directiveList.Marker,
	}
}
