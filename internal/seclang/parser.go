// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"os"
	"strconv"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"github.com/coreruleset/crslang/listener"
	"github.com/coreruleset/crslang/types"
	"github.com/coreruleset/seclang_parser/parser"
)

// ParseRuleFile parses a seclang rule file and returns a list of rules
func ParseRuleFile(filePath string) ([]Rule, error) {
	input, err := antlr.NewFileStream(filePath)
	if err != nil {
		return nil, err
	}

	lexer := parser.NewSecLangLexer(input)
	stream := antlr.NewCommonTokenStream(lexer, 0)
	p := parser.NewSecLangParser(stream)
	start := p.Configuration()
	var seclangListener listener.ExtendedSeclangParserListener
	antlr.ParseTreeWalkerDefault.Walk(&seclangListener, start)

	var rules []Rule
	for _, directiveList := range seclangListener.ConfigurationList.DirectiveList {
		for _, directive := range directiveList.Directives {
			if secRule, ok := directive.(*types.SecRule); ok {
				rule := convertSecRuleToRule(secRule)
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

// GenerateYAML generates YAML data from a Rule (deprecated, use YAMLGenerator instead)
func GenerateYAML(rule Rule) ([]byte, error) {
	generator := NewYAMLGenerator()
	return generator.Generate(rule)
}

// convertSecRuleToRule converts a crslang SecRule to our Rule type
func convertSecRuleToRule(secRule *types.SecRule) Rule {
	rule := Rule{
		RawRule: secRule.ToSeclang(),
	}

	// Extract metadata
	if secRule.Metadata != nil {
		rule.ID = strconv.Itoa(secRule.Metadata.Id)
		rule.Phase = secRule.Metadata.Phase
		rule.Rev = secRule.Metadata.Rev
		rule.Ver = secRule.Metadata.Ver
		rule.Maturity = secRule.Metadata.Maturity
		rule.Severity = secRule.Metadata.Severity
		rule.Tags = secRule.Metadata.Tags
		// Note: Description and LogData are not directly available in SecRuleMetadata
		// They might be in the Msg field or need to be extracted differently
		if secRule.Metadata.Msg != "" {
			rule.Description = secRule.Metadata.Msg
		}
	}

	// Extract variables
	for _, variable := range secRule.Variables {
		rule.Variables = append(rule.Variables, Variable{
			Name:    string(variable.Name),
			Exclude: variable.Excluded,
		})
	}

	// Extract operator
	rule.Operator = string(secRule.Operator.Name)
	if secRule.Operator.Value != "" {
		rule.Operator += ":" + secRule.Operator.Value
	}

	// Extract transformations
	for _, transformation := range secRule.Transformations.Transformations {
		rule.Transformations = append(rule.Transformations, string(transformation))
	}

	// Extract actions
	if secRule.Actions != nil {
		rule.Actions = make(map[string]string)
		actionsStr := secRule.Actions.ToString()
		// Parse actions string to extract key-value pairs
		actionParts := strings.Split(actionsStr, ",")
		for _, part := range actionParts {
			part = strings.TrimSpace(part)
			if strings.Contains(part, ":") {
				kv := strings.SplitN(part, ":", 2)
				if len(kv) == 2 {
					rule.Actions[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
				}
			} else if part != "" {
				rule.Actions[part] = ""
			}
		}
	}

	// Check if it's a chained rule
	if secRule.ChainedRule != nil {
		rule.Chain = true
		// Extract chain offset if available
		if chainedSecRule, ok := secRule.ChainedRule.(*types.SecRule); ok && chainedSecRule.Metadata != nil {
			// Try to extract chain offset from metadata or other sources
			// This might need to be implemented based on how chain offsets are stored
		}
	}

	return rule
}

// ParseRuleFileToYAML parses a seclang rule file and generates YAML output (deprecated, use YAMLGenerator instead)
func ParseRuleFileToYAML(filePath string) ([]byte, error) {
	generator := NewYAMLGenerator()
	return generator.GenerateFile(filePath)
}

// WriteYAMLToFile writes YAML data to a file
func WriteYAMLToFile(data []byte, filePath string) error {
	return os.WriteFile(filePath, data, 0644)
}
