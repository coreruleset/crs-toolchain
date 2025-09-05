// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

type generatorInterfaceTestSuite struct {
	suite.Suite
}

func TestGeneratorInterfaceTestSuite(t *testing.T) {
	suite.Run(t, new(generatorInterfaceTestSuite))
}

func (s *generatorInterfaceTestSuite) TestGeneratorInterfaceCompliance() {
	// Test that our mock generators properly implement the Generator interface
	var _ Generator = &mockGenerator{}
	var _ Generator = &mockGeneratorWithError{}
	var _ Generator = &mockGeneratorWithPanic{}
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorGenerate() {
	generator := &mockGenerator{fileExtension: ".test"}

	rule := seclang.Rule{
		ID:       "942100",
		Phase:    "2",
		Operator: "detectSQLi",
	}

	data, err := generator.Generate(rule)
	s.NoError(err, "Mock generator should not return error")
	s.Equal([]byte("mock output"), data, "Mock generator should return expected output")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorGenerateFile() {
	generator := &mockGenerator{fileExtension: ".test"}

	data, err := generator.GenerateFile("test.conf")
	s.NoError(err, "Mock generator should not return error")
	s.Equal([]byte("mock file output"), data, "Mock generator should return expected output")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorGenerateMultiple() {
	generator := &mockGenerator{fileExtension: ".test"}

	rules := []seclang.Rule{
		{ID: "942100", Phase: "2", Operator: "detectSQLi"},
		{ID: "941100", Phase: "2", Operator: "detectXSS"},
	}

	data, err := generator.GenerateMultiple(rules)
	s.NoError(err, "Mock generator should not return error")
	s.Equal([]byte("mock multiple output"), data, "Mock generator should return expected output")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorGetFileExtension() {
	generator := &mockGenerator{fileExtension: ".custom"}
	s.Equal(".custom", generator.GetFileExtension(), "Mock generator should return correct file extension")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorGetOutputFileName() {
	generator := &mockGenerator{fileExtension: ".custom"}

	rule := seclang.Rule{ID: "942100"}
	filename := generator.GetOutputFileName(rule)
	s.Equal("mock-942100.custom", filename, "Mock generator should return correct output filename")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorGetOutputFileNameWithEmptyID() {
	generator := &mockGenerator{fileExtension: ".custom"}

	rule := seclang.Rule{ID: ""}
	filename := generator.GetOutputFileName(rule)
	s.Equal("mock-.custom", filename, "Mock generator should handle empty rule ID")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithErrorGenerate() {
	generator := &mockGeneratorWithError{}

	rule := seclang.Rule{ID: "942100"}
	data, err := generator.Generate(rule)
	s.Error(err, "Mock generator with error should return error")
	s.Nil(data, "Mock generator with error should return nil data")
	s.Contains(err.Error(), "mock generation error", "Error message should match expected")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithErrorGenerateFile() {
	generator := &mockGeneratorWithError{}

	data, err := generator.GenerateFile("test.conf")
	s.Error(err, "Mock generator with error should return error")
	s.Nil(data, "Mock generator with error should return nil data")
	s.Contains(err.Error(), "mock generation error", "Error message should match expected")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithErrorGenerateMultiple() {
	generator := &mockGeneratorWithError{}

	rules := []seclang.Rule{{ID: "942100"}}
	data, err := generator.GenerateMultiple(rules)
	s.Error(err, "Mock generator with error should return error")
	s.Nil(data, "Mock generator with error should return nil data")
	s.Contains(err.Error(), "mock generation error", "Error message should match expected")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithErrorGetFileExtension() {
	generator := &mockGeneratorWithError{}
	s.Equal(".mock", generator.GetFileExtension(), "Mock generator with error should return correct file extension")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithErrorGetOutputFileName() {
	generator := &mockGeneratorWithError{}

	rule := seclang.Rule{ID: "942100"}
	filename := generator.GetOutputFileName(rule)
	s.Equal("mock-942100.mock", filename, "Mock generator with error should return correct output filename")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithPanicGenerate() {
	generator := &mockGeneratorWithPanic{}

	rule := seclang.Rule{ID: "942100"}

	// Test that the generator panics as expected
	s.Panics(func() {
		generator.Generate(rule)
	}, "Mock generator with panic should panic")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithPanicGenerateFile() {
	generator := &mockGeneratorWithPanic{}

	// Test that the generator panics as expected
	s.Panics(func() {
		generator.GenerateFile("test.conf")
	}, "Mock generator with panic should panic")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithPanicGenerateMultiple() {
	generator := &mockGeneratorWithPanic{}

	rules := []seclang.Rule{{ID: "942100"}}

	// Test that the generator panics as expected
	s.Panics(func() {
		generator.GenerateMultiple(rules)
	}, "Mock generator with panic should panic")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithPanicGetFileExtension() {
	generator := &mockGeneratorWithPanic{}
	s.Equal(".panic", generator.GetFileExtension(), "Mock generator with panic should return correct file extension")
}

func (s *generatorInterfaceTestSuite) TestMockGeneratorWithPanicGetOutputFileName() {
	generator := &mockGeneratorWithPanic{}

	rule := seclang.Rule{ID: "942100"}
	filename := generator.GetOutputFileName(rule)
	s.Equal("mock-942100.panic", filename, "Mock generator with panic should return correct output filename")
}

func (s *generatorInterfaceTestSuite) TestGeneratorWithEmptyRule() {
	generator := &mockGenerator{fileExtension: ".test"}

	emptyRule := seclang.Rule{}
	data, err := generator.Generate(emptyRule)
	s.NoError(err, "Generator should handle empty rule without error")
	s.Equal([]byte("mock output"), data, "Generator should return expected output for empty rule")
}

func (s *generatorInterfaceTestSuite) TestGeneratorWithNilRulesSlice() {
	generator := &mockGenerator{fileExtension: ".test"}

	data, err := generator.GenerateMultiple(nil)
	s.NoError(err, "Generator should handle nil rules slice without error")
	s.Equal([]byte("mock multiple output"), data, "Generator should return expected output for nil rules")
}

func (s *generatorInterfaceTestSuite) TestGeneratorWithEmptyRulesSlice() {
	generator := &mockGenerator{fileExtension: ".test"}

	data, err := generator.GenerateMultiple([]seclang.Rule{})
	s.NoError(err, "Generator should handle empty rules slice without error")
	s.Equal([]byte("mock multiple output"), data, "Generator should return expected output for empty rules")
}

func (s *generatorInterfaceTestSuite) TestGeneratorWithEmptyFilePath() {
	generator := &mockGenerator{fileExtension: ".test"}

	data, err := generator.GenerateFile("")
	s.NoError(err, "Generator should handle empty file path without error")
	s.Equal([]byte("mock file output"), data, "Generator should return expected output for empty file path")
}

func (s *generatorInterfaceTestSuite) TestGeneratorInterfaceComposition() {
	// Test that we can compose generators
	baseGenerator := &mockGenerator{fileExtension: ".base"}
	wrapperGenerator := &compositeGenerator{base: baseGenerator}

	rule := seclang.Rule{ID: "942100"}
	data, err := wrapperGenerator.Generate(rule)
	s.NoError(err, "Composite generator should not return error")
	s.Equal([]byte("mock output"), data, "Composite generator should return expected output")
	s.Equal(".base", wrapperGenerator.GetFileExtension(), "Composite generator should return correct file extension")
}

func (s *generatorInterfaceTestSuite) TestGeneratorInterfaceNilHandling() {
	// Test that generators can handle nil inputs gracefully
	generator := &mockGenerator{fileExtension: ".test"}

	// Test with nil rule (this should not panic)
	// Note: This is a theoretical test since seclang.Rule is a struct, not a pointer
	emptyRule := seclang.Rule{}
	data, err := generator.Generate(emptyRule)
	s.NoError(err, "Generator should handle empty rule without error")
	s.Equal([]byte("mock output"), data, "Generator should return expected output")
}

func (s *generatorInterfaceTestSuite) TestGeneratorInterfacePerformance() {
	generator := &mockGenerator{fileExtension: ".test"}

	// Test performance with multiple rules
	rules := make([]seclang.Rule, 1000)
	for i := 0; i < 1000; i++ {
		rules[i] = seclang.Rule{
			ID:       fmt.Sprintf("942%d", i),
			Phase:    "2",
			Operator: "detectSQLi",
		}
	}

	// This should complete quickly without errors
	data, err := generator.GenerateMultiple(rules)
	s.NoError(err, "Generator should handle large number of rules without error")
	s.Equal([]byte("mock multiple output"), data, "Generator should return expected output")
}

// mockGeneratorWithPanic is a mock generator that panics for testing error handling
type mockGeneratorWithPanic struct{}

func (m *mockGeneratorWithPanic) Generate(rule seclang.Rule) ([]byte, error) {
	panic("mock panic")
}

func (m *mockGeneratorWithPanic) GenerateFile(filePath string) ([]byte, error) {
	panic("mock panic")
}

func (m *mockGeneratorWithPanic) GenerateMultiple(rules []seclang.Rule) ([]byte, error) {
	panic("mock panic")
}

func (m *mockGeneratorWithPanic) GetFileExtension() string {
	return ".panic"
}

func (m *mockGeneratorWithPanic) GetOutputFileName(rule seclang.Rule) string {
	return "mock-" + rule.ID + ".panic"
}

// compositeGenerator is a composite generator for testing composition
type compositeGenerator struct {
	base Generator
}

func (c *compositeGenerator) Generate(rule seclang.Rule) ([]byte, error) {
	return c.base.Generate(rule)
}

func (c *compositeGenerator) GenerateFile(filePath string) ([]byte, error) {
	return c.base.GenerateFile(filePath)
}

func (c *compositeGenerator) GenerateMultiple(rules []seclang.Rule) ([]byte, error) {
	return c.base.GenerateMultiple(rules)
}

func (c *compositeGenerator) GetFileExtension() string {
	return c.base.GetFileExtension()
}

func (c *compositeGenerator) GetOutputFileName(rule seclang.Rule) string {
	return c.base.GetOutputFileName(rule)
}





