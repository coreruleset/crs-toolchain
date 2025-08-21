// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

type parserTestSuite struct {
	suite.Suite
}

func TestParserTestSuite(t *testing.T) {
	suite.Run(t, new(parserTestSuite))
}

func (s *parserTestSuite) TestParseRuleFile() {
	// Use testdata file
	testFile := "../../testdata/test-rules/test-rule.conf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		s.T().Skipf("Test file %s does not exist, skipping test", testFile)
	}

	// Test parsing the rule file
	directives, err := ParseRuleFile(testFile)
	s.Require().NoError(err, "Failed to parse rule file")
	s.NotEmpty(directives, "Expected at least one directive")

	// Find the first rule directive
	var ruleWithCondition *RuleWithCondition
	for _, directive := range directives {
		if rule, ok := directive.(*RuleWithCondition); ok {
			ruleWithCondition = rule
			break
		}
	}
	s.NotNil(ruleWithCondition, "Expected to find a rule directive")

	// Test rule metadata
	s.Equal(942100, ruleWithCondition.Metadata.Id, "Expected rule ID 942100")
	s.Equal("2", ruleWithCondition.Metadata.Phase, "Expected phase 2")

	// Test YAML generation using the new generator
	yamlGenerator := NewYAMLGenerator()
	directiveList, err := ParseRuleFileToDirectiveList(testFile)
	s.Require().NoError(err, "Failed to parse rule file to directive list")
	
	yamlData, err := yamlGenerator.GenerateDirectiveList(directiveList)
	s.Require().NoError(err, "Failed to generate YAML")
	s.NotEmpty(yamlData, "Generated YAML should not be empty")

	// Test writing YAML to file
	outputFile := testFile + ".yaml"
	err = WriteYAMLToFile(yamlData, outputFile)
	s.Require().NoError(err, "Failed to write YAML file")
	defer os.Remove(outputFile)

	// Verify the file was created
	_, err = os.Stat(outputFile)
	s.False(os.IsNotExist(err), "YAML file should be created")
}

func (s *parserTestSuite) TestParseRuleFileToYAML() {
	// Use testdata file
	testFile := "../../testdata/test-rules/test-rule.conf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		s.T().Skipf("Test file %s does not exist, skipping test", testFile)
	}

	// Test parsing and generating YAML in one step
	yamlData, err := ParseRuleFileToYAML(testFile)
	s.Require().NoError(err, "Failed to parse rule file to YAML")
	s.NotEmpty(yamlData, "Generated YAML should not be empty")

	// Verify the YAML contains expected content
	yamlStr := string(yamlData)
	s.T().Logf("Generated YAML: %s", yamlStr)
	s.Contains(yamlStr, "942100", "Generated YAML should contain rule ID")
	s.Contains(yamlStr, "phase", "Generated YAML should contain phase information")
}

func (s *parserTestSuite) TestParseRuleFileToDirectiveList() {
	// Use testdata file
	testFile := "../../testdata/test-rules/test-rule.conf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		s.T().Skipf("Test file %s does not exist, skipping test", testFile)
	}

	// Test parsing the rule file to directive list
	directiveList, err := ParseRuleFileToDirectiveList(testFile)
	s.Require().NoError(err, "Failed to parse rule file to directive list")
	s.NotNil(directiveList, "Expected directive list to be created")
	s.Equal("test-rule", directiveList.ID, "Expected directive list ID to match filename")
	s.NotEmpty(directiveList.Directives, "Expected at least one directive")

	// Verify we have rule directives
	ruleCount := 0
	for _, directive := range directiveList.Directives {
		if _, ok := directive.(*RuleWithCondition); ok {
			ruleCount++
		}
	}
	s.Equal(2, ruleCount, "Expected 2 rule directives")
}
