// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

type generatorFactoryTestSuite struct {
	suite.Suite
}

func TestGeneratorFactoryTestSuite(t *testing.T) {
	suite.Run(t, new(generatorFactoryTestSuite))
}

func (s *generatorFactoryTestSuite) TestNewGeneratorFactory() {
	factory := NewGeneratorFactory()
	s.NotNil(factory, "GeneratorFactory should not be nil")
	s.NotNil(factory.generators, "Generators map should not be nil")
}

func (s *generatorFactoryTestSuite) TestNewGeneratorFactoryMultipleInstances() {
	// Test that multiple factory instances are independent
	factory1 := NewGeneratorFactory()
	factory2 := NewGeneratorFactory()

	s.NotSame(factory1, factory2, "Factory instances should be different")

	// Test that both have the same default generators
	generator1, err1 := factory1.GetGenerator(YAMLFormat)
	generator2, err2 := factory2.GetGenerator(YAMLFormat)

	s.NoError(err1, "First factory should have YAML generator")
	s.NoError(err2, "Second factory should have YAML generator")
	// Note: Generators might be the same instance due to singleton pattern in seclang package
	s.NotNil(generator1, "First generator should not be nil")
	s.NotNil(generator2, "Second generator should not be nil")
}

func (s *generatorFactoryTestSuite) TestGetGeneratorYAML() {
	factory := NewGeneratorFactory()

	generator, err := factory.GetGenerator(YAMLFormat)
	s.NoError(err, "Should get YAML generator without error")
	s.NotNil(generator, "YAML generator should not be nil")
	s.Equal(".yaml", generator.GetFileExtension(), "YAML generator should have .yaml extension")
}

func (s *generatorFactoryTestSuite) TestGetGeneratorJSON() {
	factory := NewGeneratorFactory()

	generator, err := factory.GetGenerator(JSONFormat)
	s.NoError(err, "Should get JSON generator without error")
	s.NotNil(generator, "JSON generator should not be nil")
	s.Equal(".json", generator.GetFileExtension(), "JSON generator should have .json extension")
}

func (s *generatorFactoryTestSuite) TestGetGeneratorSeclang() {
	factory := NewGeneratorFactory()

	generator, err := factory.GetGenerator(SeclangFormat)
	s.NoError(err, "Should get Seclang generator without error")
	s.NotNil(generator, "Seclang generator should not be nil")
	s.Equal(".conf", generator.GetFileExtension(), "Seclang generator should have .conf extension")
}

func (s *generatorFactoryTestSuite) TestGetGeneratorInvalid() {
	factory := NewGeneratorFactory()

	generator, err := factory.GetGenerator("invalid")
	s.Error(err, "Should return error for invalid format")
	s.Nil(generator, "Generator should be nil for invalid format")
	s.Contains(err.Error(), "unsupported output format", "Error message should mention unsupported format")
}

func (s *generatorFactoryTestSuite) TestGetGeneratorEmptyString() {
	factory := NewGeneratorFactory()

	generator, err := factory.GetGenerator("")
	s.Error(err, "Should return error for empty format")
	s.Nil(generator, "Generator should be nil for empty format")
	s.Contains(err.Error(), "unsupported output format", "Error message should mention unsupported format")
}

func (s *generatorFactoryTestSuite) TestGetGeneratorCaseSensitive() {
	factory := NewGeneratorFactory()

	// Test case sensitivity
	generator, err := factory.GetGenerator("YAML")
	s.Error(err, "Should return error for uppercase format")
	s.Nil(generator, "Generator should be nil for uppercase format")

	generator, err = factory.GetGenerator("yaml")
	s.NoError(err, "Should get generator for lowercase format")
	s.NotNil(generator, "Generator should not be nil for lowercase format")
}

func (s *generatorFactoryTestSuite) TestRegisterGenerator() {
	factory := NewGeneratorFactory()

	// Create a custom generator
	customGenerator := &mockGenerator{
		fileExtension: ".custom",
	}

	// Register the custom generator
	factory.RegisterGenerator("custom", customGenerator)

	// Test that we can get the custom generator
	retrievedGenerator, err := factory.GetGenerator("custom")
	s.NoError(err, "Should get custom generator without error")
	s.Equal(customGenerator, retrievedGenerator, "Should return the same custom generator")
	s.Equal(".custom", retrievedGenerator.GetFileExtension(), "Custom generator should have correct extension")
}

func (s *generatorFactoryTestSuite) TestRegisterGeneratorOverwrite() {
	factory := NewGeneratorFactory()

	// Create custom generators
	customGenerator1 := &mockGenerator{fileExtension: ".custom1"}
	customGenerator2 := &mockGenerator{fileExtension: ".custom2"}

	// Register first generator
	factory.RegisterGenerator("custom", customGenerator1)

	// Register second generator (should overwrite)
	factory.RegisterGenerator("custom", customGenerator2)

	// Test that we get the second generator
	retrievedGenerator, err := factory.GetGenerator("custom")
	s.NoError(err, "Should get overwritten generator without error")
	s.Equal(customGenerator2, retrievedGenerator, "Should return the overwritten generator")
	s.Equal(".custom2", retrievedGenerator.GetFileExtension(), "Overwritten generator should have correct extension")
}

func (s *generatorFactoryTestSuite) TestRegisterGeneratorNil() {
	factory := NewGeneratorFactory()

	// Test registering nil generator
	factory.RegisterGenerator("nil", nil)

	// Test that we can get the nil generator
	retrievedGenerator, err := factory.GetGenerator("nil")
	s.NoError(err, "Should get nil generator without error")
	s.Nil(retrievedGenerator, "Should return nil generator")
}

func (s *generatorFactoryTestSuite) TestRegisterGeneratorOverwriteDefault() {
	factory := NewGeneratorFactory()

	// Create a custom generator
	customGenerator := &mockGenerator{fileExtension: ".custom"}

	// Overwrite the default YAML generator
	factory.RegisterGenerator(YAMLFormat, customGenerator)

	// Test that we get the custom generator instead of the default
	retrievedGenerator, err := factory.GetGenerator(YAMLFormat)
	s.NoError(err, "Should get custom generator without error")
	s.Equal(customGenerator, retrievedGenerator, "Should return the custom generator")
	s.Equal(".custom", retrievedGenerator.GetFileExtension(), "Custom generator should have correct extension")
}

func (s *generatorFactoryTestSuite) TestGetSupportedFormats() {
	factory := NewGeneratorFactory()

	formats := factory.GetSupportedFormats()
	s.NotEmpty(formats, "Should return supported formats")

	// Check that all expected formats are present
	expectedFormats := []OutputFormat{YAMLFormat, JSONFormat, SeclangFormat}
	for _, expected := range expectedFormats {
		s.Contains(formats, expected, "Should contain expected format")
	}

	// Check that we have exactly the expected number of formats
	s.Len(formats, len(expectedFormats), "Should have exactly the expected number of formats")
}

func (s *generatorFactoryTestSuite) TestGetSupportedFormatsAfterRegistration() {
	factory := NewGeneratorFactory()

	// Get initial formats
	initialFormats := factory.GetSupportedFormats()
	initialCount := len(initialFormats)

	// Register a new generator
	customGenerator := &mockGenerator{fileExtension: ".custom"}
	factory.RegisterGenerator("custom", customGenerator)

	// Get formats after registration
	newFormats := factory.GetSupportedFormats()
	s.Len(newFormats, initialCount+1, "Should have one more format after registration")
	s.Contains(newFormats, OutputFormat("custom"), "Should contain the newly registered format")
}

func (s *generatorFactoryTestSuite) TestGetSupportedFormatsAfterOverwrite() {
	factory := NewGeneratorFactory()

	// Get initial formats
	initialFormats := factory.GetSupportedFormats()
	initialCount := len(initialFormats)

	// Overwrite an existing generator
	customGenerator := &mockGenerator{fileExtension: ".custom"}
	factory.RegisterGenerator(YAMLFormat, customGenerator)

	// Get formats after overwrite
	newFormats := factory.GetSupportedFormats()
	s.Len(newFormats, initialCount, "Should have the same number of formats after overwrite")
	s.Contains(newFormats, YAMLFormat, "Should still contain the overwritten format")
}

func (s *generatorFactoryTestSuite) TestIsFormatSupported() {
	factory := NewGeneratorFactory()

	// Test supported formats
	s.True(factory.IsFormatSupported(YAMLFormat), "YAML format should be supported")
	s.True(factory.IsFormatSupported(JSONFormat), "JSON format should be supported")
	s.True(factory.IsFormatSupported(SeclangFormat), "Seclang format should be supported")

	// Test unsupported formats
	s.False(factory.IsFormatSupported("invalid"), "Invalid format should not be supported")
	s.False(factory.IsFormatSupported(""), "Empty format should not be supported")
	s.False(factory.IsFormatSupported("YAML"), "Uppercase format should not be supported")
}

func (s *generatorFactoryTestSuite) TestIsFormatSupportedAfterRegistration() {
	factory := NewGeneratorFactory()

	// Test that custom format is not supported initially
	s.False(factory.IsFormatSupported("custom"), "Custom format should not be supported initially")

	// Register custom generator
	customGenerator := &mockGenerator{fileExtension: ".custom"}
	factory.RegisterGenerator("custom", customGenerator)

	// Test that custom format is now supported
	s.True(factory.IsFormatSupported("custom"), "Custom format should be supported after registration")
}

func (s *generatorFactoryTestSuite) TestIsFormatSupportedAfterOverwrite() {
	factory := NewGeneratorFactory()

	// Test that YAML format is supported initially
	s.True(factory.IsFormatSupported(YAMLFormat), "YAML format should be supported initially")

	// Overwrite with nil generator
	factory.RegisterGenerator(YAMLFormat, nil)

	// Test that YAML format is still supported (even with nil generator)
	s.True(factory.IsFormatSupported(YAMLFormat), "YAML format should still be supported after overwrite")
}

func (s *generatorFactoryTestSuite) TestOutputFormatConstants() {
	// Test that the constants have the expected values
	s.Equal(OutputFormat("yaml"), YAMLFormat, "YAMLFormat should have correct value")
	s.Equal(OutputFormat("json"), JSONFormat, "JSONFormat should have correct value")
	s.Equal(OutputFormat("seclang"), SeclangFormat, "SeclangFormat should have correct value")
}

func (s *generatorFactoryTestSuite) TestOutputFormatTypeConversion() {
	// Test that OutputFormat can be converted to string
	yamlStr := string(YAMLFormat)
	s.Equal("yaml", yamlStr, "YAMLFormat should convert to string correctly")

	jsonStr := string(JSONFormat)
	s.Equal("json", jsonStr, "JSONFormat should convert to string correctly")

	seclangStr := string(SeclangFormat)
	s.Equal("seclang", seclangStr, "SeclangFormat should convert to string correctly")
}

func (s *generatorFactoryTestSuite) TestGeneratorFactoryConcurrency() {
	factory := NewGeneratorFactory()

	// Test concurrent access to the factory (read-only operations)
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			// Test getting a generator (read-only operation)
			generator, err := factory.GetGenerator(YAMLFormat)
			s.NoError(err, "Should get generator without error")
			s.NotNil(generator, "Generator should not be nil")

			// Test checking if format is supported (read-only operation)
			s.True(factory.IsFormatSupported(YAMLFormat), "YAML format should be supported")

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify that the factory still works correctly
	formats := factory.GetSupportedFormats()
	s.Len(formats, 3, "Should have exactly 3 default formats")
}

func (s *generatorFactoryTestSuite) TestGeneratorFactoryMemoryUsage() {
	// Test that creating multiple factories doesn't cause memory issues
	factories := make([]*GeneratorFactory, 100)
	for i := 0; i < 100; i++ {
		factories[i] = NewGeneratorFactory()
	}

	// Test that all factories work correctly
	for i, factory := range factories {
		generator, err := factory.GetGenerator(YAMLFormat)
		s.NoError(err, fmt.Sprintf("Factory %d should get YAML generator without error", i))
		s.NotNil(generator, fmt.Sprintf("Factory %d should have non-nil generator", i))
	}
}

// mockGenerator is a mock implementation of the Generator interface for testing
type mockGenerator struct {
	fileExtension string
}

func (m *mockGenerator) Generate(rule seclang.Rule) ([]byte, error) {
	return []byte("mock output"), nil
}

func (m *mockGenerator) GenerateFile(filePath string) ([]byte, error) {
	return []byte("mock file output"), nil
}

func (m *mockGenerator) GenerateMultiple(rules []seclang.Rule) ([]byte, error) {
	return []byte("mock multiple output"), nil
}

func (m *mockGenerator) GetFileExtension() string {
	return m.fileExtension
}

func (m *mockGenerator) GetOutputFileName(rule seclang.Rule) string {
	return "mock-" + rule.ID + m.fileExtension
}
