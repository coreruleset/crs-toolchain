// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type generateCommandTestSuite struct {
	suite.Suite
	cmdContext *internal.CommandContext
}

func TestGenerateCommandTestSuite(t *testing.T) {
	suite.Run(t, new(generateCommandTestSuite))
}

func (s *generateCommandTestSuite) SetupTest() {
	s.cmdContext = internal.NewCommandContext("")
}

func (s *generateCommandTestSuite) TestNew() {
	cmd := New(s.cmdContext)
	s.NotNil(cmd, "Generate command should not be nil")
	s.Equal("generate", cmd.Use, "Command use should be 'generate'")
	s.Equal("Commands that generate artifacts from seclang rules", cmd.Short, "Command short description should match")
}

func (s *generateCommandTestSuite) TestCommandStructure() {
	cmd := New(s.cmdContext)

	// Test that the command has the expected subcommands
	subcommands := cmd.Commands()
	s.Len(subcommands, 2, "Should have exactly 2 subcommands")

	// Check for yaml and seclang subcommands (order may vary)
	yamlFound := false
	seclangFound := false

	for _, subcmd := range subcommands {
		if subcmd.Use == "yaml [RULE_ID]" {
			yamlFound = true
		} else if subcmd.Use == "seclang [YAML_FILE]" {
			seclangFound = true
		}
	}

	s.True(yamlFound, "Should have yaml subcommand")
	s.True(seclangFound, "Should have seclang subcommand")
}

func (s *generateCommandTestSuite) TestPersistentFlags() {
	cmd := New(s.cmdContext)

	// Test output-dir flag
	outputDirFlag := cmd.PersistentFlags().Lookup("output-dir")
	s.NotNil(outputDirFlag, "Should have output-dir persistent flag")
	s.Equal("t", outputDirFlag.Shorthand, "Output-dir flag should have shorthand 't'")
	s.Equal("generate-output", outputDirFlag.DefValue, "Output-dir flag should have default value 'generate-output'")
}

func (s *generateCommandTestSuite) TestCommandHelp() {
	cmd := New(s.cmdContext)

	// Test that help text contains expected content
	helpText := cmd.Long
	s.Contains(helpText, "generate various artifacts", "Help text should mention generating artifacts")
	s.Contains(helpText, "seclang rules", "Help text should mention seclang rules")
	s.Contains(helpText, "YAML files", "Help text should mention YAML files")
}

func (s *generateCommandTestSuite) TestCommandExecution() {
	cmd := New(s.cmdContext)

	// Test that command can be executed without arguments
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	s.NoError(err, "Command should execute without error when no arguments provided")
}

func (s *generateCommandTestSuite) TestCommandWithHelp() {
	cmd := New(s.cmdContext)

	// Test help flag
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	s.NoError(err, "Command should execute with help flag")
}

func (s *generateCommandTestSuite) TestCommandWithOutputDir() {
	cmd := New(s.cmdContext)

	// Test output-dir flag
	cmd.SetArgs([]string{"--output-dir", "test-output"})
	err := cmd.Execute()
	s.NoError(err, "Command should execute with output-dir flag")

	// Verify the flag value
	outputDir, err := cmd.PersistentFlags().GetString("output-dir")
	s.NoError(err, "Should be able to get output-dir flag value")
	s.Equal("test-output", outputDir, "Output-dir flag should be set correctly")
}

func (s *generateCommandTestSuite) TestCommandWithShorthandOutputDir() {
	cmd := New(s.cmdContext)

	// Test output-dir shorthand flag
	cmd.SetArgs([]string{"-t", "test-output-short"})
	err := cmd.Execute()
	s.NoError(err, "Command should execute with output-dir shorthand flag")

	// Verify the flag value
	outputDir, err := cmd.PersistentFlags().GetString("output-dir")
	s.NoError(err, "Should be able to get output-dir flag value")
	s.Equal("test-output-short", outputDir, "Output-dir flag should be set correctly with shorthand")
}
