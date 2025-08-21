// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind represents the type of directive
type Kind string

const (
	CommentKind        Kind = "comment"
	ConfigurationKind  Kind = "configuration"
	RuleKind           Kind = "rule"
	DefaultActionKind  Kind = "defaultaction"
	RemoveKind         Kind = "remove"
	UpdateTargetKind   Kind = "update_target"
	UpdateActionKind   Kind = "update_action"
)

// CommentMetadata represents comment metadata
type CommentMetadata struct {
	Comment string `yaml:"comment,omitempty"`
}

// SecRuleMetadata represents comprehensive rule metadata
type SecRuleMetadata struct {
	Comment  string   `yaml:"comment,omitempty"`
	Phase    string   `yaml:"phase,omitempty"`
	Id       int      `yaml:"id,omitempty"`
	Message  string   `yaml:"message,omitempty"`
	Severity string   `yaml:"severity,omitempty"`
	Tags     []string `yaml:"tags,omitempty"`
	Version  string   `yaml:"version,omitempty"`
	Maturity string   `yaml:"maturity,omitempty"`
	Rev      string   `yaml:"revision,omitempty"`
}

// Variable represents a seclang variable
type Variable struct {
	Name    string   `yaml:"name"`
	Scope   string   `yaml:"scope,omitempty"`
	Count   string   `yaml:"count,omitempty"`
	Exclude bool     `yaml:"exclude,omitempty"`
	Values  []string `yaml:"values,omitempty"`
}

// Collection represents a collection of variables
type Collection struct {
	Name      string   `yaml:"name"`
	Arguments []string `yaml:"arguments,omitempty"`
	Count     bool     `yaml:"count,omitempty"`
}

// Operator represents a seclang operator
type Operator struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value,omitempty"`
	Negate bool  `yaml:"negate,omitempty"`
}

// Transformations represents seclang transformations
type Transformations struct {
	Transformations []string `yaml:"transformations,omitempty"`
}

// Action represents a seclang action
type Action struct {
	Action string `yaml:"action"`
	Param  string `yaml:"param,omitempty"`
}

// SeclangActions represents structured seclang actions
type SeclangActions struct {
	DisruptiveAction    *Action  `yaml:"disruptiveAction,omitempty"`
	NonDisruptiveActions []Action `yaml:"non-disruptiveActions,omitempty"`
	DataActions         []Action `yaml:"dataActions,omitempty"`
	FlowActions         []Action `yaml:"flowActions,omitempty"`
}

// Condition represents a rule condition
type Condition interface {
	ConditionToSeclang() string
}

// SecRuleCondition represents a SecRule condition
type SecRuleCondition struct {
	Variables       []Variable   `yaml:"variables,omitempty"`
	Collections     []Collection `yaml:"collections,omitempty"`
	Operator        Operator     `yaml:"operator"`
	Transformations `yaml:",inline,omitempty"`
}

func (s SecRuleCondition) ConditionToSeclang() string {
	return "SecRule condition"
}

// SecActionCondition represents a SecAction condition
type SecActionCondition struct {
	AlwaysMatch     bool `yaml:"alwaysMatch,omitempty"`
	Transformations `yaml:",inline,omitempty"`
}

func (s SecActionCondition) ConditionToSeclang() string {
	return "SecAction condition"
}

// ScriptCondition represents a script condition
type ScriptCondition struct {
	Script string `yaml:"script,omitempty"`
}

func (s ScriptCondition) ConditionToSeclang() string {
	return "Script condition"
}

// RuleWithCondition represents a rule with conditions (matching crslang format)
type RuleWithCondition struct {
	Kind        Kind               `yaml:"kind"`
	Metadata    SecRuleMetadata    `yaml:"metadata,omitempty"`
	Conditions  []Condition        `yaml:"conditions,omitempty"`
	Actions     SeclangActions     `yaml:"actions,omitempty"`
	ChainedRule *RuleWithCondition `yaml:"chainedRule,omitempty"`
}

// CommentDirective represents a comment directive
type CommentDirective struct {
	Kind     Kind            `yaml:"kind"`
	Metadata CommentMetadata `yaml:",inline"`
}

// ConfigurationDirective represents a configuration directive
type ConfigurationDirective struct {
	Kind      Kind            `yaml:"kind"`
	Metadata  *CommentMetadata `yaml:",inline"`
	Name      string          `yaml:"name"`
	Parameter string          `yaml:"parameter"`
}

// SeclangDirective represents any seclang directive
type SeclangDirective interface {
	ToSeclang() string
}

// DirectiveList represents a group of directives (following crslang pattern)
type DirectiveList struct {
	ID         string              `yaml:"id"`
	Directives []SeclangDirective  `yaml:"directives,omitempty"`
	Marker     *ConfigurationDirective `yaml:"marker,omitempty"`
}

// ConfigurationList represents the top-level structure (following crslang pattern)
type ConfigurationList struct {
	DirectiveList []DirectiveList `yaml:"directivelist,omitempty"`
}

// Rule represents a seclang rule (legacy format, kept for backward compatibility)
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

// ToSeclang methods
func (c CommentDirective) ToSeclang() string {
	return c.Metadata.Comment
}

func (c ConfigurationDirective) ToSeclang() string {
	result := ""
	if c.Metadata != nil {
		result += c.Metadata.Comment
	}
	result += c.Name + " " + c.Parameter
	return result + "\n"
}

func (r RuleWithCondition) ToSeclang() string {
	var seclang strings.Builder

	// Start with SecRule
	seclang.WriteString("SecRule ")

	// Add variables/collections
	if len(r.Conditions) > 0 {
		if secRuleCond, ok := r.Conditions[0].(SecRuleCondition); ok {
			// Add collections
			if len(secRuleCond.Collections) > 0 {
				var vars []string
				for _, coll := range secRuleCond.Collections {
					if coll.Count {
						vars = append(vars, "&"+coll.Name)
					} else {
						vars = append(vars, coll.Name)
					}
				}
				seclang.WriteString(strings.Join(vars, " "))
			} else if len(secRuleCond.Variables) > 0 {
				// Add variables
				var vars []string
				for _, v := range secRuleCond.Variables {
					if v.Exclude {
						vars = append(vars, "!"+v.Name)
					} else {
						vars = append(vars, v.Name)
					}
				}
				seclang.WriteString(strings.Join(vars, " "))
			} else {
				seclang.WriteString("ARGS") // Default
			}

			// Add operator
			seclang.WriteString(" \"@")
			seclang.WriteString(secRuleCond.Operator.Name)
			if secRuleCond.Operator.Value != "" {
				seclang.WriteString(":")
				seclang.WriteString(secRuleCond.Operator.Value)
			}
			seclang.WriteString("\" \\\n\t\"")
		}
	} else {
		seclang.WriteString("ARGS \"@rx\" \\\n\t\"")
	}

	// Build actions string
	var actions []string

	// Add ID
	if r.Metadata.Id != 0 {
		actions = append(actions, fmt.Sprintf("id:%d", r.Metadata.Id))
	}

	// Add phase
	if r.Metadata.Phase != "" {
		actions = append(actions, "phase:"+r.Metadata.Phase)
	}

	// Add disruptive action
	if r.Actions.DisruptiveAction != nil {
		actions = append(actions, r.Actions.DisruptiveAction.Action)
	}

	// Add non-disruptive actions
	for _, action := range r.Actions.NonDisruptiveActions {
		if action.Param != "" {
			actions = append(actions, action.Action+":"+action.Param)
		} else {
			actions = append(actions, action.Action)
		}
	}

	// Add message if available
	if r.Metadata.Message != "" {
		actions = append(actions, "msg:'"+r.Metadata.Message+"'")
	}

	// Add tags if available
	if len(r.Metadata.Tags) > 0 {
		actions = append(actions, "tag:'"+strings.Join(r.Metadata.Tags, ",")+"'")
	}

	// Add other metadata
	if r.Metadata.Rev != "" {
		actions = append(actions, "rev:"+r.Metadata.Rev)
	}
	if r.Metadata.Version != "" {
		actions = append(actions, "ver:"+r.Metadata.Version)
	}
	if r.Metadata.Maturity != "" {
		actions = append(actions, "maturity:"+r.Metadata.Maturity)
	}

	seclang.WriteString(strings.Join(actions, ",\\\n\t"))
	seclang.WriteString("\"")

	return seclang.String()
}
