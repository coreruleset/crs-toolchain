// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"testing"
)

func TestFilterAdministrativeRules(t *testing.T) {
	// Create a test directive list with both administrative and normal rules
	directiveList := &DirectiveList{
		ID: "test-rules",
		Directives: []SeclangDirective{
			// Administrative rule (ID ending in 1)
			&RuleWithCondition{
				Kind: RuleKind,
				Metadata: SecRuleMetadata{
					Id:      932101,
					Phase:   "2",
					Message: "Administrative rule",
				},
			},
			// Normal rule (ID ending in 0)
			&RuleWithCondition{
				Kind: RuleKind,
				Metadata: SecRuleMetadata{
					Id:      932100,
					Phase:   "2",
					Message: "Normal rule",
				},
			},
			// Administrative rule (ID ending in 5)
			&RuleWithCondition{
				Kind: RuleKind,
				Metadata: SecRuleMetadata{
					Id:      920015,
					Phase:   "1",
					Message: "Another administrative rule",
				},
			},
			// Comment directive (should be kept)
			CommentDirective{
				Kind:     CommentKind,
				Metadata: CommentMetadata{Comment: "This is a comment"},
			},
			// Normal rule (ID ending in 9)
			&RuleWithCondition{
				Kind: RuleKind,
				Metadata: SecRuleMetadata{
					Id:      941109,
					Phase:   "2",
					Message: "Another normal rule",
				},
			},
		},
	}

	// Create YAML generator and filter the rules
	generator := NewYAMLGenerator()
	filteredList := generator.filterAdministrativeRules(directiveList)

	// Verify that administrative rules are filtered out
	expectedCount := 3 // 2 normal rules + 1 comment
	if len(filteredList.Directives) != expectedCount {
		t.Errorf("Expected %d directives after filtering, got %d", expectedCount, len(filteredList.Directives))
	}

	// Verify that only non-administrative rules remain
	ruleCount := 0
	commentCount := 0
	for _, directive := range filteredList.Directives {
		if ruleWithCondition, ok := directive.(*RuleWithCondition); ok {
			ruleCount++
			// Verify that remaining rules are not administrative
			if isAdministrativeRule(ruleWithCondition.Metadata.Id) {
				t.Errorf("Administrative rule with ID %d should have been filtered out", ruleWithCondition.Metadata.Id)
			}
		} else if _, ok := directive.(CommentDirective); ok {
			commentCount++
		}
	}

	// Verify we have the expected number of rules and comments
	if ruleCount != 2 {
		t.Errorf("Expected 2 rules after filtering, got %d", ruleCount)
	}
	if commentCount != 1 {
		t.Errorf("Expected 1 comment after filtering, got %d", commentCount)
	}
}
