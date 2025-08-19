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
	rules, err := ParseRuleFile(testFile)
	s.Require().NoError(err, "Failed to parse rule file")
	s.NotEmpty(rules, "Expected at least one rule")

	rule := rules[0]
	s.Equal("942100", rule.ID, "Expected rule ID 942100")
	s.Equal("2", rule.Phase, "Expected phase 2")

	// Test YAML generation
	yamlData, err := GenerateYAML(rule)
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
