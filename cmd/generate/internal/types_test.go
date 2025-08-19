// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type typesTestSuite struct {
	suite.Suite
	outerContext *internal.CommandContext
	logger       zerolog.Logger
}

func TestTypesTestSuite(t *testing.T) {
	suite.Run(t, new(typesTestSuite))
}

func (s *typesTestSuite) SetupTest() {
	s.outerContext = internal.NewCommandContext("")
	s.logger = zerolog.New(nil)
}

func (s *typesTestSuite) TestNewCommandContext() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)
	s.NotNil(cmdContext, "CommandContext should not be nil")
	s.Equal(s.outerContext, cmdContext.OuterContext, "OuterContext should be set correctly")
	s.Equal(&s.logger, cmdContext.Logger, "Logger should be set correctly")
}

func (s *typesTestSuite) TestCommandContextFields() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test initial field values
	s.Empty(cmdContext.Id, "Id should be empty initially")
	s.Empty(cmdContext.FileName, "FileName should be empty initially")
	s.Equal(uint8(0), cmdContext.ChainOffset, "ChainOffset should be 0 initially")
	s.False(cmdContext.UseStdin, "UseStdin should be false initially")
}

func (s *typesTestSuite) TestCommandContextSetFields() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Set fields
	cmdContext.Id = "942100"
	cmdContext.FileName = "test.conf"
	cmdContext.ChainOffset = 2
	cmdContext.UseStdin = true

	// Verify fields are set correctly
	s.Equal("942100", cmdContext.Id, "Id should be set correctly")
	s.Equal("test.conf", cmdContext.FileName, "FileName should be set correctly")
	s.Equal(uint8(2), cmdContext.ChainOffset, "ChainOffset should be set correctly")
	s.True(cmdContext.UseStdin, "UseStdin should be set correctly")
}

func (s *typesTestSuite) TestGetOutputDir() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Create a mock command with flags
	cmd := &cobra.Command{}
	cmd.Flags().StringP("output-dir", "t", "generate-output", "Output directory for generated files")

	// Test default output directory
	outputDir := cmdContext.GetOutputDir(cmd)
	s.Equal("generate-output", outputDir, "Should return default output directory")

	// Test custom output directory
	cmd.Flags().Set("output-dir", "custom-output")
	outputDir = cmdContext.GetOutputDir(cmd)
	s.Equal("custom-output", outputDir, "Should return custom output directory")
}

func (s *typesTestSuite) TestGetOutputDirWithInvalidFlag() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Create a command without the output-dir flag
	cmd := &cobra.Command{}

	// Test fallback to default
	outputDir := cmdContext.GetOutputDir(cmd)
	s.Equal("generate-output", outputDir, "Should fallback to default when flag is not available")
}

func (s *typesTestSuite) TestRootContext() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	rootContext := cmdContext.RootContext()
	s.NotNil(rootContext, "RootContext should not be nil")
}

func (s *typesTestSuite) TestCommandContextEquality() {
	cmdContext1 := NewCommandContext(s.outerContext, &s.logger)
	cmdContext2 := NewCommandContext(s.outerContext, &s.logger)

	// Set same values
	cmdContext1.Id = "942100"
	cmdContext2.Id = "942100"

	// Test that they have the same values but are different instances
	s.Equal(cmdContext1.Id, cmdContext2.Id, "Ids should be equal")
	s.NotSame(cmdContext1, cmdContext2, "Contexts should be different instances")
}

func (s *typesTestSuite) TestCommandContextWithNilLogger() {
	cmdContext := NewCommandContext(s.outerContext, nil)
	s.NotNil(cmdContext, "CommandContext should not be nil even with nil logger")
	s.Nil(cmdContext.Logger, "Logger should be nil when passed nil")
}

func (s *typesTestSuite) TestCommandContextWithNilOuterContext() {
	cmdContext := NewCommandContext(nil, &s.logger)
	s.NotNil(cmdContext, "CommandContext should not be nil even with nil outer context")
	s.Nil(cmdContext.OuterContext, "OuterContext should be nil when passed nil")
}
