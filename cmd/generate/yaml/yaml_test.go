// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package yaml

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

type yamlCommandTestSuite struct {
	suite.Suite
	tempDir  string
	rulesDir string
}

func TestYamlCommandTestSuite(t *testing.T) {
	suite.Run(t, new(yamlCommandTestSuite))
}

func (s *yamlCommandTestSuite) SetupTest() {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "test_generate_yaml")
	s.Require().NoError(err, "Failed to create temp directory")
	s.tempDir = tempDir

	// Create a test rules directory
	rulesDir := filepath.Join(tempDir, "rules")
	err = os.MkdirAll(rulesDir, 0755)
	s.Require().NoError(err, "Failed to create rules directory")
	s.rulesDir = rulesDir
}

func (s *yamlCommandTestSuite) TearDownTest() {
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

func (s *yamlCommandTestSuite) TestNew() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)
	s.NotNil(cmd, "Failed to create yaml command")
	s.Equal("yaml [RULE_ID]", cmd.Use, "Command use should match expected")
	s.Equal("Generate YAML files from seclang rules", cmd.Short, "Command short description should match")
}

func (s *yamlCommandTestSuite) TestCommandStructure() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test that the command has the expected flags
	allFlag := cmd.Flags().Lookup("all")
	s.NotNil(allFlag, "Command should have 'all' flag")
	s.Equal("a", allFlag.Shorthand, "All flag should have shorthand 'a'")
	s.False(allFlag.DefValue == "true", "All flag should default to false")
}

func (s *yamlCommandTestSuite) TestCommandHelp() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test that help text contains expected content
	helpText := cmd.Long
	s.Contains(helpText, "Generate YAML files from seclang rules", "Help text should mention YAML generation")
	s.Contains(helpText, "RULE_ID", "Help text should mention RULE_ID parameter")
	s.Contains(helpText, "chained rule", "Help text should mention chained rules")
}

func (s *yamlCommandTestSuite) TestCommandArgsValidation() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with no arguments and no --all flag
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	s.Error(err, "Should return error when no arguments and no --all flag")
	s.Contains(err.Error(), "expected either RULE_ID or flag, found neither", "Error message should mention required arguments")

	// Test with both RULE_ID and --all flag
	cmd.SetArgs([]string{"942100", "--all"})
	err = cmd.Execute()
	s.Error(err, "Should return error when both RULE_ID and --all flag are provided")
	s.Contains(err.Error(), "expected either RULE_ID or flag, found both", "Error message should mention exclusive arguments")
}

func (s *yamlCommandTestSuite) TestCommandWithValidRuleId() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with valid rule ID
	cmd.SetArgs([]string{"942100"})
	err = cmd.Execute()
	s.NoError(err, "Should execute without error when valid rule ID is provided")
}

func (s *yamlCommandTestSuite) TestCommandWithAllFlag() {
	// Create test rule files
	testRuleContent1 := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile1 := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile1, []byte(testRuleContent1), 0644)
	s.Require().NoError(err, "Failed to create test rule file 1")

	testRuleContent2 := `SecRule ARGS "@detectXSS" "id:941100,phase:2,block,log"`
	ruleFile2 := filepath.Join(s.rulesDir, "941100.conf")
	err = os.WriteFile(ruleFile2, []byte(testRuleContent2), 0644)
	s.Require().NoError(err, "Failed to create test rule file 2")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with --all flag
	cmd.SetArgs([]string{"--all"})
	err = cmd.Execute()
	s.NoError(err, "Should execute without error when --all flag is provided")
}

func (s *yamlCommandTestSuite) TestCommandWithShorthandAllFlag() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with shorthand --all flag
	cmd.SetArgs([]string{"-a"})
	err = cmd.Execute()
	s.NoError(err, "Should execute without error when shorthand --all flag is provided")
}

func (s *yamlCommandTestSuite) TestCommandWithHelp() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test help flag
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	s.NoError(err, "Command should execute with help flag")
}

func (s *yamlCommandTestSuite) TestCommandWithInvalidRuleId() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with invalid rule ID
	cmd.SetArgs([]string{"invalid-rule"})
	err := cmd.Execute()
	s.Error(err, "Should return error for invalid rule ID")
	s.Contains(err.Error(), "failed to match rule ID", "Error message should mention rule ID matching")
}

func (s *yamlCommandTestSuite) TestCommandWithChainedRule() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with chained rule ID
	cmd.SetArgs([]string{"942100-chain2"})
	err = cmd.Execute()
	s.NoError(err, "Should execute without error when chained rule ID is provided")
}

func (s *yamlCommandTestSuite) TestPerformYamlGenerationSingleRule() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Create a mock command for testing
	mockCmd := &cobra.Command{}
	mockCmd.Flags().StringP("output-dir", "t", "generate-output", "Output directory for generated files")

	// Test processing single rule
	performYamlGeneration(false, buildCmdContext, mockCmd)

	// Check that output directory was created
	outputDir := "generate-output"
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
	defer os.RemoveAll(outputDir)
}

func (s *yamlCommandTestSuite) TestPerformYamlGenerationAllRules() {
	// Create test rule files
	testRuleContent1 := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile1 := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile1, []byte(testRuleContent1), 0644)
	s.Require().NoError(err, "Failed to create test rule file 1")

	testRuleContent2 := `SecRule ARGS "@detectXSS" "id:941100,phase:2,block,log"`
	ruleFile2 := filepath.Join(s.rulesDir, "941100.conf")
	err = os.WriteFile(ruleFile2, []byte(testRuleContent2), 0644)
	s.Require().NoError(err, "Failed to create test rule file 2")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Create a mock command for testing
	mockCmd := &cobra.Command{}
	mockCmd.Flags().StringP("output-dir", "t", "generate-output", "Output directory for generated files")

	// Test processing all rules
	performYamlGeneration(true, buildCmdContext, mockCmd)

	// Check that output directory was created
	outputDir := "generate-output"
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
	defer os.RemoveAll(outputDir)
}

func (s *yamlCommandTestSuite) TestPerformYamlGenerationWithCustomOutputDir() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Create a mock command for testing with custom output directory
	mockCmd := &cobra.Command{}
	mockCmd.Flags().StringP("output-dir", "t", "custom-output", "Output directory for generated files")

	// Test processing with custom output directory
	performYamlGeneration(false, buildCmdContext, mockCmd)

	// Check that custom output directory was created
	outputDir := "custom-output"
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Custom output directory should be created")
	defer os.RemoveAll(outputDir)
}

func (s *yamlCommandTestSuite) TestProcessRuleFile() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	outputDir := filepath.Join(s.tempDir, "output")

	// Test processing rule file
	processRuleFile(ruleFile, outputDir, buildCmdContext)

	// Check that output directory was created
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
}

func (s *yamlCommandTestSuite) TestProcessRuleFileWithInvalidFile() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	outputDir := filepath.Join(s.tempDir, "output")

	// Test processing non-existent rule file
	processRuleFile("non-existent.conf", outputDir, buildCmdContext)

	// Check that output directory was created (should be created even for invalid files)
	_, err := os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created even for non-existent file")
}

func (s *yamlCommandTestSuite) TestProcessRuleFileWithEmptyFile() {
	// Create an empty test rule file
	ruleFile := filepath.Join(s.rulesDir, "empty.conf")
	err := os.WriteFile(ruleFile, []byte(""), 0644)
	s.Require().NoError(err, "Failed to create empty test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	outputDir := filepath.Join(s.tempDir, "output")

	// Test processing empty rule file
	processRuleFile(ruleFile, outputDir, buildCmdContext)

	// Check that output directory was created
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
}

func (s *yamlCommandTestSuite) TestProcessRuleFileWithInvalidRuleContent() {
	// Create a test rule file with invalid content
	testRuleContent := `Invalid SecRule content that should cause parsing error`
	ruleFile := filepath.Join(s.rulesDir, "invalid.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create invalid test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	outputDir := filepath.Join(s.tempDir, "output")

	// Test processing invalid rule file
	processRuleFile(ruleFile, outputDir, buildCmdContext)

	// Check that output directory was created
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
}

func (s *yamlCommandTestSuite) TestProcessRuleFileWithMultipleRules() {
	// Create a test rule file with multiple rules
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"
SecRule ARGS "@detectXSS" "id:941100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "multiple.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file with multiple rules")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	outputDir := filepath.Join(s.tempDir, "output")

	// Test processing rule file with multiple rules
	processRuleFile(ruleFile, outputDir, buildCmdContext)

	// Check that output directory was created
	_, err = os.Stat(outputDir)
	s.False(os.IsNotExist(err), "Output directory should be created")
}

func (s *yamlCommandTestSuite) TestBuildFlags() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test that the command has the expected flags
	allFlag := cmd.Flags().Lookup("all")
	s.NotNil(allFlag, "Command should have 'all' flag")
	s.Equal("a", allFlag.Shorthand, "All flag should have shorthand 'a'")
	s.False(allFlag.DefValue == "true", "All flag should default to false")

	// Test flag description
	allFlagUsage := allFlag.Usage
	s.Contains(allFlagUsage, "Instead of supplying a RULE_ID", "Flag usage should mention RULE_ID alternative")
	s.Contains(allFlagUsage, "generate YAML for all rules", "Flag usage should mention generating for all rules")
}

func (s *yamlCommandTestSuite) TestCommandWithMaxArgs() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with too many arguments
	cmd.SetArgs([]string{"942100", "941100", "extra"})
	err := cmd.Execute()
	s.Error(err, "Should return error when too many arguments are provided")
}

func (s *yamlCommandTestSuite) TestCommandWithEmptyRuleId() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with empty rule ID
	cmd.SetArgs([]string{""})
	err := cmd.Execute()
	s.Error(err, "Should return error for empty rule ID")
}

func (s *yamlCommandTestSuite) TestCommandWithSpecialCharactersInRuleId() {
	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with special characters in rule ID
	cmd.SetArgs([]string{"942@100"})
	err := cmd.Execute()
	s.Error(err, "Should return error for rule ID with special characters")
}

func (s *yamlCommandTestSuite) TestCommandWithLeadingZerosInRuleId() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:0942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "0942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with leading zeros in rule ID
	cmd.SetArgs([]string{"0942100"})
	err = cmd.Execute()
	s.Error(err, "Should return error for rule ID with leading zeros")
	s.Contains(err.Error(), "failed to match rule ID", "Error message should mention rule ID matching")
}

func (s *yamlCommandTestSuite) TestCommandWithComplexChainedRule() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with complex chained rule ID
	cmd.SetArgs([]string{"942100-chain10"})
	err = cmd.Execute()
	s.NoError(err, "Should execute without error when complex chained rule ID is provided")
}

func (s *yamlCommandTestSuite) TestCommandWithFilenameExtension() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with filename extension
	cmd.SetArgs([]string{"942100.conf"})
	err = cmd.Execute()
	s.Error(err, "Should return error for filename with extension")
	s.Contains(err.Error(), "failed to match rule ID", "Error message should mention rule ID matching")
}

func (s *yamlCommandTestSuite) TestCommandWithFilenameWithoutExtension() {
	// Create a test rule file
	testRuleContent := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,log"`
	ruleFile := filepath.Join(s.rulesDir, "942100.conf")
	err := os.WriteFile(ruleFile, []byte(testRuleContent), 0644)
	s.Require().NoError(err, "Failed to create test rule file")

	// Create context
	cmdContext := internal.NewCommandContext(s.tempDir)
	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &log.Logger)

	// Test the command creation
	cmd := New(buildCmdContext)

	// Test with filename without extension
	cmd.SetArgs([]string{"942100"})
	err = cmd.Execute()
	s.NoError(err, "Should execute without error when filename without extension is provided")
}

// copyFile is a helper function to copy files for testing
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return err
	}

	return nil
}
