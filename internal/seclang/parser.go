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

// ParseRuleFile parses a seclang rule file and returns a list of directives
func ParseRuleFile(filePath string) ([]SeclangDirective, error) {
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

	var directives []SeclangDirective
	for _, directiveList := range seclangListener.ConfigurationList.DirectiveList {
		for _, directive := range directiveList.Directives {
			convertedDirective := convertDirective(directive)
			if convertedDirective != nil {
				directives = append(directives, convertedDirective)
			}
		}
	}

	return directives, nil
}

// ParseRuleFileToDirectiveList parses a seclang rule file and returns a DirectiveList
func ParseRuleFileToDirectiveList(filePath string) (*DirectiveList, error) {
	directives, err := ParseRuleFile(filePath)
	if err != nil {
		return nil, err
	}

	// Extract filename without extension for ID
	fileName := strings.TrimSuffix(filePath[strings.LastIndex(filePath, "/")+1:], ".conf")
	
	return &DirectiveList{
		ID:         fileName,
		Directives: directives,
	}, nil
}

// GenerateYAML generates YAML data from a Rule (deprecated, use YAMLGenerator instead)
func GenerateYAML(rule Rule) ([]byte, error) {
	generator := NewYAMLGenerator()
	return generator.Generate(rule)
}

// convertDirective converts a crslang directive to our SeclangDirective type
func convertDirective(directive interface{}) SeclangDirective {
	switch d := directive.(type) {
	case *types.SecRule:
		return convertSecRuleToRuleWithCondition(d)
	case *types.SecAction:
		return convertSecActionToRuleWithCondition(d)
	case *types.SecRuleScript:
		return convertSecRuleScriptToRuleWithCondition(d)
	case *types.CommentMetadata:
		return CommentDirective{
			Kind:     CommentKind,
			Metadata: CommentMetadata{Comment: d.Comment},
		}
	case *types.ConfigurationDirective:
		return ConfigurationDirective{
			Kind:      ConfigurationKind,
			Metadata:  &CommentMetadata{Comment: d.Metadata.Comment},
			Name:      string(d.Name),
			Parameter: d.Parameter,
		}
	default:
		return nil
	}
}

// convertSecRuleToRuleWithCondition converts a crslang SecRule to our RuleWithCondition type
func convertSecRuleToRuleWithCondition(secRule *types.SecRule) *RuleWithCondition {
	rule := &RuleWithCondition{
		Kind: RuleKind,
		Metadata: SecRuleMetadata{
			Comment:  secRule.Metadata.Comment,
			Phase:    secRule.Metadata.Phase,
			Id:       secRule.Metadata.Id,
			Message:  secRule.Metadata.Msg,
			Severity: secRule.Metadata.Severity,
			Tags:     secRule.Metadata.Tags,
			Version:  secRule.Metadata.Ver,
			Maturity: secRule.Metadata.Maturity,
			Rev:      secRule.Metadata.Rev,
		},
		Conditions: []Condition{
			SecRuleCondition{
				Variables:   convertVariables(secRule.Variables),
				Collections: convertCollections(secRule.Collections),
				Operator:    convertOperator(secRule.Operator),
				Transformations: Transformations{
					Transformations: convertTransformations(secRule.Transformations.Transformations),
				},
			},
		},
		Actions: convertActions(secRule.Actions),
	}

	// Handle chained rule
	if secRule.ChainedRule != nil {
		if chainedSecRule, ok := secRule.ChainedRule.(*types.SecRule); ok {
			rule.ChainedRule = convertSecRuleToRuleWithCondition(chainedSecRule)
		}
	}

	return rule
}

// convertSecActionToRuleWithCondition converts a crslang SecAction to our RuleWithCondition type
func convertSecActionToRuleWithCondition(secAction *types.SecAction) *RuleWithCondition {
	return &RuleWithCondition{
		Kind: RuleKind,
		Metadata: SecRuleMetadata{
			Comment:  secAction.Metadata.Comment,
			Phase:    secAction.Metadata.Phase,
			Id:       secAction.Metadata.Id,
			Message:  secAction.Metadata.Msg,
			Severity: secAction.Metadata.Severity,
			Tags:     secAction.Metadata.Tags,
			Version:  secAction.Metadata.Ver,
			Maturity: secAction.Metadata.Maturity,
			Rev:      secAction.Metadata.Rev,
		},
		Conditions: []Condition{
			SecActionCondition{
				AlwaysMatch: true,
				Transformations: Transformations{
					Transformations: convertTransformations(secAction.Transformations.Transformations),
				},
			},
		},
		Actions: convertActions(secAction.Actions),
	}
}

// convertSecRuleScriptToRuleWithCondition converts a crslang SecRuleScript to our RuleWithCondition type
func convertSecRuleScriptToRuleWithCondition(secRuleScript *types.SecRuleScript) *RuleWithCondition {
	return &RuleWithCondition{
		Kind: RuleKind,
		Metadata: SecRuleMetadata{
			Comment:  secRuleScript.Metadata.Comment,
			Phase:    secRuleScript.Metadata.Phase,
			Id:       secRuleScript.Metadata.Id,
			Message:  secRuleScript.Metadata.Msg,
			Severity: secRuleScript.Metadata.Severity,
			Tags:     secRuleScript.Metadata.Tags,
			Version:  secRuleScript.Metadata.Ver,
			Maturity: secRuleScript.Metadata.Maturity,
			Rev:      secRuleScript.Metadata.Rev,
		},
		Conditions: []Condition{
			ScriptCondition{
				Script: secRuleScript.ScriptPath,
			},
		},
		Actions: convertActions(secRuleScript.Actions),
	}
}

// convertVariables converts crslang variables to our Variable type
func convertVariables(variables []types.Variable) []Variable {
	var result []Variable
	for _, v := range variables {
		result = append(result, Variable{
			Name:    string(v.Name),
			Exclude: v.Excluded,
		})
	}
	return result
}

// convertCollections converts crslang collections to our Collection type
func convertCollections(collections []types.Collection) []Collection {
	var result []Collection
	for _, c := range collections {
		result = append(result, Collection{
			Name:      string(c.Name),
			Arguments: c.Arguments,
			Count:     c.Count,
		})
	}
	return result
}

// convertOperator converts crslang operator to our Operator type
func convertOperator(operator types.Operator) Operator {
	return Operator{
		Name:   string(operator.Name),
		Value:  operator.Value,
		Negate: operator.Negate,
	}
}

// convertTransformations converts crslang transformations to our string slice
func convertTransformations(transformations []types.Transformation) []string {
	var result []string
	for _, t := range transformations {
		result = append(result, string(t))
	}
	return result
}

// convertActions converts crslang actions to our SeclangActions type
func convertActions(actions *types.SeclangActions) SeclangActions {
	if actions == nil {
		return SeclangActions{}
	}

	result := SeclangActions{}

	// Convert disruptive action
	if actions.DisruptiveAction.Action != "" {
		result.DisruptiveAction = &Action{
			Action: string(actions.DisruptiveAction.Action),
			Param:  actions.DisruptiveAction.Param,
		}
	}

	// Convert non-disruptive actions
	for _, action := range actions.NonDisruptiveActions {
		result.NonDisruptiveActions = append(result.NonDisruptiveActions, Action{
			Action: string(action.Action),
			Param:  action.Param,
		})
	}

	// Convert data actions
	for _, action := range actions.DataActions {
		result.DataActions = append(result.DataActions, Action{
			Action: string(action.Action),
			Param:  action.Param,
		})
	}

	// Convert flow actions
	for _, action := range actions.FlowActions {
		result.FlowActions = append(result.FlowActions, Action{
			Action: string(action.Action),
			Param:  action.Param,
		})
	}

	return result
}

// convertSecRuleToRule converts a crslang SecRule to our Rule type (legacy, kept for backward compatibility)
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
