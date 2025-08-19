// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"os"
	"path/filepath"
	"testing"

	buildInternal "github.com/coreruleset/crs-toolchain/v2/cmd/generate/internal"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

type seclangCommandTestSuite struct {
	suite.Suite
	tempDir    string
	cmdContext *buildInternal.CommandContext
}

func TestSeclangCommandTestSuite(t *testing.T) {
	suite.Run(t, new(seclangCommandTestSuite))
}

func (s *seclangCommandTestSuite) SetupTest() {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "test_generate_seclang")
	s.Require().NoError(err, "Failed to create temp directory")
	s.tempDir = tempDir

	// Create context
	outerContext := internal.NewCommandContext(tempDir)
	s.cmdContext = buildInternal.NewCommandContext(outerContext, &log.Logger)
}

func (s *seclangCommandTestSuite) TearDownTest() {
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

func (s *seclangCommandTestSuite) TestNew() {
	cmd := New(s.cmdContext)
	s.NotNil(cmd, "Seclang command should not be nil")
	s.Equal("seclang [YAML_FILE]", cmd.Use, "Command use should be 'seclang [YAML_FILE]'")
}

func (s *seclangCommandTestSuite) TestCommandStructure() {
	cmd := New(s.cmdContext)

	// Test that the command has the expected flags
	allFlag := cmd.Flags().Lookup("all")
	s.NotNil(allFlag, "Command should have 'all' flag")
	s.Equal("a", allFlag.Shorthand, "All flag should have shorthand 'a'")
}

func (s *seclangCommandTestSuite) TestCommandHelp() {
	cmd := New(s.cmdContext)

	// Test that help text contains expected content
	helpText := cmd.Long
	s.Contains(helpText, "Generate seclang files from CRSLang YAML files", "Help text should mention generating seclang files")
	s.Contains(helpText, "reverse operation", "Help text should mention reverse operation")
	s.Contains(helpText, "YAML_FILE", "Help text should mention YAML_FILE parameter")
}

func (s *seclangCommandTestSuite) TestCommandArgsValidation() {
	cmd := New(s.cmdContext)

	// Test with no arguments and no --all flag
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	s.Error(err, "Should return error when no arguments and no --all flag")
	s.Contains(err.Error(), "expected either YAML_FILE or --all flag", "Error message should mention required arguments")
}

func (s *seclangCommandTestSuite) TestCommandWithYamlFile() {
	cmd := New(s.cmdContext)

	// Test with YAML file argument
	cmd.SetArgs([]string{"test.yaml"})
	err := cmd.Execute()
	s.NoError(err, "Should execute without error when YAML file is provided")
}

func (s *seclangCommandTestSuite) TestCommandWithAllFlag() {
	cmd := New(s.cmdContext)

	// Test with --all flag
	cmd.SetArgs([]string{"--all"})
	err := cmd.Execute()
	s.NoError(err, "Should execute without error when --all flag is provided")
}

func (s *seclangCommandTestSuite) TestCommandWithBothArgsAndAllFlag() {
	cmd := New(s.cmdContext)

	// Test with both YAML file and --all flag (should fail)
	cmd.SetArgs([]string{"test.yaml", "--all"})
	err := cmd.Execute()
	s.Error(err, "Should return error when both YAML file and --all flag are provided")
	s.Contains(err.Error(), "expected either YAML_FILE or --all flag", "Error message should mention exclusive arguments")
}

func (s *seclangCommandTestSuite) TestCommandWithHelp() {
	cmd := New(s.cmdContext)

	// Test help flag
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	s.NoError(err, "Command should execute with help flag")
}

func (s *seclangCommandTestSuite) TestCommandWithShorthandAllFlag() {
	cmd := New(s.cmdContext)

	// Test with shorthand --all flag
	cmd.SetArgs([]string{"-a"})
	err := cmd.Execute()
	s.NoError(err, "Should execute without error when shorthand --all flag is provided")
}

func (s *seclangCommandTestSuite) TestPerformSeclangGeneration() {
	// Create a test YAML file
	testYamlFile := filepath.Join(s.tempDir, "test-rule.yaml")
	testYamlContent := `id: "942100"
phase: "2"
operator: "detectSQLi"
description: "SQL Injection Attack Detected via libinjection"
raw_rule: "SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,block,log\""`

	err := os.WriteFile(testYamlFile, []byte(testYamlContent), 0644)
	s.Require().NoError(err, "Failed to create test YAML file")

	// Create a mock command for testing
	mockCmd := &cobra.Command{}
	mockCmd.Flags().StringP("output-dir", "t", "generate-output", "Output directory for generated files")

	// Test processing single YAML file
	performSeclangGeneration(false, s.cmdContext, mockCmd)

	// Check that output directory was created
	outputDir := "generate-output"
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
	defer os.RemoveAll(outputDir)
}

func (s *seclangCommandTestSuite) TestPerformSeclangGenerationAll() {
	// Create test YAML files
	testYamlFile1 := filepath.Join(s.tempDir, "test-rule1.yaml")
	testYamlContent1 := `id: "942100"
phase: "2"
operator: "detectSQLi"
description: "SQL Injection Attack Detected via libinjection"
raw_rule: "SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,block,log\""`

	err := os.WriteFile(testYamlFile1, []byte(testYamlContent1), 0644)
	s.Require().NoError(err, "Failed to create test YAML file 1")

	testYamlFile2 := filepath.Join(s.tempDir, "test-rule2.yaml")
	testYamlContent2 := `id: "941100"
phase: "2"
operator: "detectXSS"
description: "XSS Attack Detected via libinjection"
raw_rule: "SecRule ARGS \"@detectXSS\" \"id:941100,phase:2,block,log\""`

	err = os.WriteFile(testYamlFile2, []byte(testYamlContent2), 0644)
	s.Require().NoError(err, "Failed to create test YAML file 2")

	// Create a mock command for testing
	mockCmd := &cobra.Command{}
	mockCmd.Flags().StringP("output-dir", "t", "generate-output", "Output directory for generated files")

	// Test processing all YAML files
	performSeclangGeneration(true, s.cmdContext, mockCmd)

	// Check that output directory was created
	outputDir := "generate-output"
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
	defer os.RemoveAll(outputDir)
}

func (s *seclangCommandTestSuite) TestProcessYamlFile() {
	// Create a test YAML file
	testYamlFile := filepath.Join(s.tempDir, "test-rule.yaml")
	testYamlContent := `id: "942100"
phase: "2"
operator: "detectSQLi"
description: "SQL Injection Attack Detected via libinjection"
raw_rule: "SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,block,log\""`

	err := os.WriteFile(testYamlFile, []byte(testYamlContent), 0644)
	s.Require().NoError(err, "Failed to create test YAML file")

	outputDir := filepath.Join(s.tempDir, "output")

	// Create output directory first
	err = os.MkdirAll(outputDir, 0755)
	s.Require().NoError(err, "Failed to create output directory")

	// Test processing YAML file
	processYamlFile(testYamlFile, outputDir, s.cmdContext)

	// Check that output file was created
	expectedOutputFile := filepath.Join(outputDir, "test-rule.conf")
	_, err = os.Stat(expectedOutputFile)
	s.False(os.IsNotExist(err), "Output file should be created")

	// Check that the output file contains expected content
	outputContent, err := os.ReadFile(expectedOutputFile)
	s.NoError(err, "Should be able to read output file")
	s.Contains(string(outputContent), "SecRule", "Output should contain SecRule")
	s.Contains(string(outputContent), "942100", "Output should contain rule ID")
}

func (s *seclangCommandTestSuite) TestProcessYamlFileWithInvalidYaml() {
	// Create an invalid YAML file
	testYamlFile := filepath.Join(s.tempDir, "invalid-rule.yaml")
	testYamlContent := `invalid: yaml: content:`

	err := os.WriteFile(testYamlFile, []byte(testYamlContent), 0644)
	s.Require().NoError(err, "Failed to create invalid YAML file")

	outputDir := filepath.Join(s.tempDir, "output")

	// Create output directory first
	err = os.MkdirAll(outputDir, 0755)
	s.Require().NoError(err, "Failed to create output directory")

	// Test processing invalid YAML file (should not panic)
	processYamlFile(testYamlFile, outputDir, s.cmdContext)

	// Check that output directory exists
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should exist")
}

func (s *seclangCommandTestSuite) TestProcessYamlFileWithNonExistentFile() {
	outputDir := filepath.Join(s.tempDir, "output")

	// Create output directory first
	err := os.MkdirAll(outputDir, 0755)
	s.Require().NoError(err, "Failed to create output directory")

	// Test processing non-existent file (should not panic)
	processYamlFile("non-existent.yaml", outputDir, s.cmdContext)

	// Check that output directory exists
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should exist")
}
