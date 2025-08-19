// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

type seclangGeneratorTestSuite struct {
	suite.Suite
}

func TestSeclangGeneratorTestSuite(t *testing.T) {
	suite.Run(t, new(seclangGeneratorTestSuite))
}

func (s *seclangGeneratorTestSuite) TestSeclangGenerator() {
	// Create a test rule
	rule := Rule{
		ID:          "942100",
		Phase:       "2",
		Operator:    "detectSQLi",
		Description: "SQL Injection Attack Detected via libinjection",
		LogData:     "Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}",
		Actions: map[string]string{
			"block": "",
			"log":   "",
		},
		RawRule: `SecRule ARGS "@detectSQLi" \
	"id:942100,\
	phase:2,\
	block,\
	log,\
	msg:'SQL Injection Attack Detected via libinjection',\
	logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"`,
	}

	// Create seclang generator
	generator := NewSeclangGenerator()

	// Test single rule generation
	output, err := generator.Generate(rule)
	s.Require().NoError(err, "Failed to generate seclang")

	outputStr := string(output)
	s.T().Logf("Generated seclang: %s", outputStr)

	// Verify the output contains expected elements
	s.Contains(outputStr, "SecRule", "Generated seclang should contain 'SecRule'")
	s.Contains(outputStr, "942100", "Generated seclang should contain rule ID")
	s.Contains(outputStr, "detectSQLi", "Generated seclang should contain operator")

	// Test file extension
	s.Equal(".conf", generator.GetFileExtension(), "File extension should be '.conf'")

	// Test output filename
	expectedFilename := "rule-942100.conf"
	s.Equal(expectedFilename, generator.GetOutputFileName(rule), "Output filename should match expected")
}

func (s *seclangGeneratorTestSuite) TestSeclangGeneratorMultiple() {
	// Create test rules
	rules := []Rule{
		{
			ID:          "942100",
			Phase:       "2",
			Operator:    "detectSQLi",
			Description: "SQL Injection Attack Detected via libinjection",
			RawRule:     `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`,
		},
		{
			ID:          "941100",
			Phase:       "2",
			Operator:    "detectXSS",
			Description: "XSS Attack Detected via libinjection",
			RawRule:     `SecRule ARGS "@detectXSS" "id:941100,phase:2,block,log"`,
		},
	}

	// Create seclang generator
	generator := NewSeclangGenerator()

	// Test multiple rules generation
	output, err := generator.GenerateMultiple(rules)
	s.Require().NoError(err, "Failed to generate multiple seclang rules")

	outputStr := string(output)
	s.T().Logf("Generated seclang: %s", outputStr)

	// Verify both rules are present
	s.Contains(outputStr, "942100", "Generated seclang should contain first rule ID")
	s.Contains(outputStr, "941100", "Generated seclang should contain second rule ID")
	s.Contains(outputStr, "detectSQLi", "Generated seclang should contain first rule operator")
	s.Contains(outputStr, "detectXSS", "Generated seclang should contain second rule operator")
}

func (s *seclangGeneratorTestSuite) TestSeclangGeneratorConstructFromRule() {
	// Create a test rule without RawRule to test construction
	rule := Rule{
		ID:          "942100",
		Phase:       "2",
		Operator:    "detectSQLi",
		Description: "SQL Injection Attack Detected via libinjection",
		LogData:     "Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}",
		Actions: map[string]string{
			"block": "",
			"log":   "",
		},
		Variables: []Variable{
			{Name: "ARGS", Exclude: false},
		},
		Tags:     []string{"attack", "sql-injection"},
		Rev:      "1",
		Ver:      "3.0",
		Maturity: "9",
		Accuracy: "8",
	}

	// Create seclang generator
	generator := NewSeclangGenerator()

	// Test generation (should construct from fields since RawRule is empty)
	output, err := generator.Generate(rule)
	s.Require().NoError(err, "Failed to generate seclang")

	outputStr := string(output)
	s.T().Logf("Generated seclang: %s", outputStr)

	// Verify the constructed seclang contains expected elements
	s.Contains(outputStr, "SecRule", "Generated seclang should contain 'SecRule'")
	s.Contains(outputStr, "ARGS", "Generated seclang should contain variable")
	s.Contains(outputStr, "@detectSQLi", "Generated seclang should contain operator")
	s.Contains(outputStr, "id:942100", "Generated seclang should contain rule ID")
	s.Contains(outputStr, "phase:2", "Generated seclang should contain phase")
	s.Contains(outputStr, "block", "Generated seclang should contain block action")
	s.Contains(outputStr, "log", "Generated seclang should contain log action")
}

func (s *seclangGeneratorTestSuite) TestSeclangGeneratorFile() {
	// Use testdata file
	testFile := "../../testdata/test-rules/test-rule.conf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		s.T().Skipf("Test file %s does not exist, skipping test", testFile)
	}

	// Create seclang generator
	generator := NewSeclangGenerator()

	// Test file generation
	output, err := generator.GenerateFile(testFile)
	s.Require().NoError(err, "Failed to generate seclang from file")

	outputStr := string(output)
	s.T().Logf("Generated seclang from file: %s", outputStr)

	// Verify the output contains expected elements
	s.Contains(outputStr, "SecRule", "Generated seclang should contain 'SecRule'")
	s.Contains(outputStr, "942100", "Generated seclang should contain first rule ID")
	s.Contains(outputStr, "941100", "Generated seclang should contain second rule ID")
}
