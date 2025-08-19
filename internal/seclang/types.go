// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"regexp"
)

// Rule represents a seclang rule
type Rule struct {
	ID              string            `yaml:"id"`
	Phase           string            `yaml:"phase"`
	Action          string            `yaml:"action"`
	Variables       []Variable        `yaml:"variables,omitempty"`
	Operator        string            `yaml:"operator"`
	Transformations []string          `yaml:"transformations,omitempty"`
	Actions         map[string]string `yaml:"actions,omitempty"`
	Chain           bool              `yaml:"chain,omitempty"`
	ChainOffset     uint8             `yaml:"chain_offset,omitempty"`
	Description     string            `yaml:"description,omitempty"`
	Severity        string            `yaml:"severity,omitempty"`
	LogData         string            `yaml:"logdata,omitempty"`
	Tags            []string          `yaml:"tags,omitempty"`
	Rev             string            `yaml:"rev,omitempty"`
	Ver             string            `yaml:"ver,omitempty"`
	Maturity        string            `yaml:"maturity,omitempty"`
	Accuracy        string            `yaml:"accuracy,omitempty"`
	RawRule         string            `yaml:"raw_rule,omitempty"`
}

// DirectiveList represents a group of rules (following crslang pattern)
type DirectiveList struct {
	ID         string `yaml:"id"`
	Directives []Rule `yaml:"directives,omitempty"`
}

// ConfigurationList represents the top-level structure (following crslang pattern)
type ConfigurationList struct {
	DirectiveList []DirectiveList `yaml:"directivelist,omitempty"`
}

// Variable represents a seclang variable
type Variable struct {
	Name    string   `yaml:"name"`
	Scope   string   `yaml:"scope,omitempty"`
	Count   string   `yaml:"count,omitempty"`
	Exclude bool     `yaml:"exclude,omitempty"`
	Values  []string `yaml:"values,omitempty"`
}

// RuleParser handles parsing of seclang rules
type RuleParser struct {
	ruleRegex *regexp.Regexp
}

// NewRuleParser creates a new rule parser
func NewRuleParser() *RuleParser {
	return &RuleParser{
		ruleRegex: regexp.MustCompile(`(?i)^SecRule\s+([^\\]+)\s+([^\\]+)\s+([^\\]+)(?:\s+(.+))?$`),
	}
}
