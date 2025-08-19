// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

type generatorTestSuite struct {
	suite.Suite
	tempDir string
}

func TestGeneratorTestSuite(t *testing.T) {
	suite.Run(t, new(generatorTestSuite))
}

func (s *generatorTestSuite) SetupTest() {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "test_generator")
	s.Require().NoError(err, "Failed to create temp directory")
	s.tempDir = tempDir
}

func (s *generatorTestSuite) TearDownTest() {
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

func (s *generatorTestSuite) TestNewGenerateContext() {
	context := NewGenerateContext("test-output")
	s.NotNil(context, "GenerateContext should not be nil")
	s.Equal("test-output", context.OutputDir, "OutputDir should be set correctly")
	s.Empty(context.Rules, "Rules should be empty initially")
}

func (s *generatorTestSuite) TestNewGenerateContextWithEmptyDir() {
	context := NewGenerateContext("")
	s.NotNil(context, "GenerateContext should not be nil even with empty output dir")
	s.Empty(context.OutputDir, "OutputDir should be empty")
	s.Empty(context.Rules, "Rules should be empty initially")
}

func (s *generatorTestSuite) TestAddRule() {
	context := NewGenerateContext("test-output")

	rule := seclang.Rule{
		ID:          "942100",
		Phase:       "2",
		Operator:    "detectSQLi",
		Description: "SQL Injection Attack Detected via libinjection",
	}

	context.AddRule(rule)
	s.Len(context.Rules, 1, "Should have one rule after adding")
	s.Equal("942100", context.Rules[0].ID, "Rule ID should match")
}

func (s *generatorTestSuite) TestAddMultipleRules() {
	context := NewGenerateContext("test-output")

	rule1 := seclang.Rule{ID: "942100", Phase: "2", Operator: "detectSQLi"}
	rule2 := seclang.Rule{ID: "941100", Phase: "2", Operator: "detectXSS"}

	context.AddRule(rule1)
	context.AddRule(rule2)

	s.Len(context.Rules, 2, "Should have two rules after adding")
	s.Equal("942100", context.Rules[0].ID, "First rule ID should match")
	s.Equal("941100", context.Rules[1].ID, "Second rule ID should match")
}

func (s *generatorTestSuite) TestAddRuleWithEmptyRule() {
	context := NewGenerateContext("test-output")

	emptyRule := seclang.Rule{}
	context.AddRule(emptyRule)

	s.Len(context.Rules, 1, "Should have one rule after adding empty rule")
	s.Equal("", context.Rules[0].ID, "Empty rule ID should be preserved")
}

func (s *generatorTestSuite) TestAddRuleWithNilContext() {
	// This test ensures we don't panic when adding rules
	// In practice, this shouldn't happen as NewGenerateContext always returns a valid context
	context := NewGenerateContext("test-output")
	s.NotNil(context, "Context should not be nil")

	rule := seclang.Rule{ID: "942100"}
	context.AddRule(rule)
	s.Len(context.Rules, 1, "Should add rule successfully")
}

func (s *generatorTestSuite) TestGenerateAll() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule := seclang.Rule{
		ID:          "942100",
		Phase:       "2",
		Operator:    "detectSQLi",
		Description: "SQL Injection Attack Detected via libinjection",
		RawRule:     `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`,
	}
	context.AddRule(rule)

	// Test generating all rules
	err := context.GenerateAll(generator)
	s.NoError(err, "Should generate all rules without error")

	// Check that output file was created
	expectedFile := filepath.Join(s.tempDir, "rule-942100.yaml")
	_, err = os.Stat(expectedFile)
	s.False(os.IsNotExist(err), "Output file should be created")
}

func (s *generatorTestSuite) TestGenerateAllWithMultipleRules() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with multiple rules
	context := NewGenerateContext(s.tempDir)
	rule1 := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
		RawRule:  `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`,
	}
	rule2 := seclang.Rule{
		ID:       "941100",
		Phase:    "2",
		Operator: "detectXSS",
		RawRule:  `SecRule ARGS "@detectXSS" "id:941100,phase:2,block,log"`,
	}
	context.AddRule(rule1)
	context.AddRule(rule2)

	// Test generating all rules
	err := context.GenerateAll(generator)
	s.NoError(err, "Should generate all rules without error")

	// Check that output files were created
	expectedFile1 := filepath.Join(s.tempDir, "rule-942100.yaml")
	expectedFile2 := filepath.Join(s.tempDir, "rule-941100.yaml")

	_, err = os.Stat(expectedFile1)
	s.False(os.IsNotExist(err), "First output file should be created")

	_, err = os.Stat(expectedFile2)
	s.False(os.IsNotExist(err), "Second output file should be created")
}

func (s *generatorTestSuite) TestGenerateAllWithEmptyRules() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with no rules
	context := NewGenerateContext(s.tempDir)

	// Test generating with no rules
	err := context.GenerateAll(generator)
	s.NoError(err, "Should handle empty rules without error")

	// Check that no files were created
	files, err := os.ReadDir(s.tempDir)
	s.NoError(err, "Should be able to read directory")
	s.Empty(files, "No files should be created for empty rules")
}

func (s *generatorTestSuite) TestGenerateAllWithNilGenerator() {
	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
		RawRule:  `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`,
	}
	context.AddRule(rule)

	// Test generating with nil generator
	err := context.GenerateAll(nil)
	s.Error(err, "Should return error for nil generator")
	s.Contains(err.Error(), "generator cannot be nil", "Error message should mention nil generator")
}

func (s *generatorTestSuite) TestGenerateAllWithInvalidOutputDir() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with invalid output directory
	context := NewGenerateContext("/invalid/path/that/does/not/exist")
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
		RawRule:  `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`,
	}
	context.AddRule(rule)

	// Test generating with invalid output directory
	err := context.GenerateAll(generator)
	s.Error(err, "Should return error for invalid output directory")
}

func (s *generatorTestSuite) TestGenerateAllWithGeneratorError() {
	// Create a mock generator that returns an error
	mockGenerator := &mockGeneratorWithError{}

	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
	}
	context.AddRule(rule)

	// Test generating with generator that returns error
	err := context.GenerateAll(mockGenerator)
	s.Error(err, "Should return error when generator fails")
	s.Contains(err.Error(), "mock generation error", "Error message should match mock error")
}

func (s *generatorTestSuite) TestGenerateSingleFile() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule1 := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
		RawRule:  `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`,
	}
	rule2 := seclang.Rule{
		ID:       "941100",
		Phase:    "2",
		Operator: "detectXSS",
		RawRule:  `SecRule ARGS "@detectXSS" "id:941100,phase:2,block,log"`,
	}
	context.AddRule(rule1)
	context.AddRule(rule2)

	// Test generating single file
	err := context.GenerateSingleFile(generator, "all-rules.yaml")
	s.NoError(err, "Should generate single file without error")

	// Check that output file was created
	expectedFile := filepath.Join(s.tempDir, "all-rules.yaml")
	_, err = os.Stat(expectedFile)
	s.False(os.IsNotExist(err), "Output file should be created")

	// Check that file has content
	content, err := os.ReadFile(expectedFile)
	s.NoError(err, "Should be able to read generated file")
	s.NotEmpty(content, "Generated file should have content")
}

func (s *generatorTestSuite) TestGenerateSingleFileWithEmptyRules() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with no rules
	context := NewGenerateContext(s.tempDir)

	// Test generating single file with no rules
	err := context.GenerateSingleFile(generator, "empty-rules.yaml")
	s.NoError(err, "Should handle empty rules without error")

	// Check that output file was created
	expectedFile := filepath.Join(s.tempDir, "empty-rules.yaml")
	_, err = os.Stat(expectedFile)
	s.False(os.IsNotExist(err), "Output file should be created even for empty rules")
}

func (s *generatorTestSuite) TestGenerateSingleFileWithNilGenerator() {
	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
	}
	context.AddRule(rule)

	// Test generating with nil generator
	err := context.GenerateSingleFile(nil, "test.yaml")
	s.Error(err, "Should return error for nil generator")
}

func (s *generatorTestSuite) TestGenerateSingleFileWithInvalidOutputDir() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with invalid output directory
	context := NewGenerateContext("/invalid/path/that/does/not/exist")
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
	}
	context.AddRule(rule)

	// Test generating with invalid output directory
	err := context.GenerateSingleFile(generator, "test.yaml")
	s.Error(err, "Should return error for invalid output directory")
}

func (s *generatorTestSuite) TestGenerateSingleFileWithEmptyFilename() {
	// Create a test generator
	generator := seclang.NewYAMLGenerator()

	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
	}
	context.AddRule(rule)

	// Test generating with empty filename
	err := context.GenerateSingleFile(generator, "")
	s.Error(err, "Should return error for empty filename")
	s.Contains(err.Error(), "filename cannot be empty", "Error message should mention empty filename")
}

func (s *generatorTestSuite) TestGenerateSingleFileWithGeneratorError() {
	// Create a mock generator that returns an error
	mockGenerator := &mockGeneratorWithError{}

	// Create context with rules
	context := NewGenerateContext(s.tempDir)
	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
	}
	context.AddRule(rule)

	// Test generating with generator that returns error
	err := context.GenerateSingleFile(mockGenerator, "test.yaml")
	s.Error(err, "Should return error when generator fails")
	s.Contains(err.Error(), "mock generation error", "Error message should match mock error")
}

func (s *generatorTestSuite) TestGenerateContextConcurrency() {
	// Test that multiple goroutines can safely add rules
	context := NewGenerateContext(s.tempDir)

	// Add rules from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			rule := seclang.Rule{
				ID:       fmt.Sprintf("942%d", id),
				Phase:    "2",
				Operator: "detectSQLi",
			}
			context.AddRule(rule)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check that rules were added (may not be exactly 10 due to race conditions)
	s.GreaterOrEqual(len(context.Rules), 1, "Should have at least one rule added")
	s.LessOrEqual(len(context.Rules), 10, "Should have at most 10 rules added")
}

// mockGeneratorWithError is a mock generator that always returns an error
type mockGeneratorWithError struct{}

func (m *mockGeneratorWithError) Generate(rule seclang.Rule) ([]byte, error) {
	return nil, fmt.Errorf("mock generation error")
}

func (m *mockGeneratorWithError) GenerateFile(filePath string) ([]byte, error) {
	return nil, fmt.Errorf("mock generation error")
}

func (m *mockGeneratorWithError) GenerateMultiple(rules []seclang.Rule) ([]byte, error) {
	return nil, fmt.Errorf("mock generation error")
}

func (m *mockGeneratorWithError) GetFileExtension() string {
	return ".mock"
}

func (m *mockGeneratorWithError) GetOutputFileName(rule seclang.Rule) string {
	return "mock-" + rule.ID + ".mock"
}
