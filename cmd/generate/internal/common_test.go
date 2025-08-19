// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type commonTestSuite struct {
	suite.Suite
	outerContext *internal.CommandContext
	logger       zerolog.Logger
}

func TestCommonTestSuite(t *testing.T) {
	suite.Run(t, new(commonTestSuite))
}

func (s *commonTestSuite) SetupTest() {
	s.outerContext = internal.NewCommandContext("")
	s.logger = zerolog.New(nil)
}

func (s *commonTestSuite) TestParseRuleIdWithValidId() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with valid rule ID
	err := ParseRuleId("942100", cmdContext)
	s.NoError(err, "Should parse valid rule ID without error")
	s.Equal("942100", cmdContext.Id, "Should set the rule ID correctly")
}

func (s *commonTestSuite) TestParseRuleIdWithValidFilename() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with valid filename (6 digits)
	err := ParseRuleId("942100", cmdContext)
	s.NoError(err, "Should parse valid rule ID without error")
	s.Equal("942100", cmdContext.Id, "Should extract rule ID correctly")
}

func (s *commonTestSuite) TestParseRuleIdWithChainedRule() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with chained rule
	err := ParseRuleId("942100-chain2", cmdContext)
	s.NoError(err, "Should parse chained rule without error")
	s.Equal("942100", cmdContext.Id, "Should extract base rule ID from chained rule")
	s.Equal(uint8(2), cmdContext.ChainOffset, "Should set chain offset correctly")
}

func (s *commonTestSuite) TestParseRuleIdWithInvalidInput() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with invalid input
	err := ParseRuleId("invalid-rule", cmdContext)
	s.Error(err, "Should return error for invalid rule ID")
	s.Contains(err.Error(), "failed to match rule ID", "Error message should mention rule ID matching")
}

func (s *commonTestSuite) TestParseRuleIdWithEmptyInput() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with empty input
	err := ParseRuleId("", cmdContext)
	s.Error(err, "Should return error for empty input")
}

func (s *commonTestSuite) TestParseRuleIdWithComplexChainedRule() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with complex chained rule
	err := ParseRuleId("942100-chain10", cmdContext)
	s.NoError(err, "Should parse complex chained rule without error")
	s.Equal("942100", cmdContext.Id, "Should extract base rule ID from complex chained rule")
	s.Equal(uint8(10), cmdContext.ChainOffset, "Should set chain offset correctly for double digits")
}

func (s *commonTestSuite) TestParseRuleIdWithFilenameAndExtension() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with filename that has .ra extension (which is supported by the regex)
	err := ParseRuleId("942100-chain3.ra", cmdContext)
	s.NoError(err, "Should parse filename with .ra extension without error")
	s.Equal("942100", cmdContext.Id, "Should extract rule ID from filename with .ra extension")
	s.Equal(uint8(3), cmdContext.ChainOffset, "Should set chain offset correctly")
}

func (s *commonTestSuite) TestParseRuleIdWithLeadingZeros() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with rule ID that has leading zeros (6 digits total)
	err := ParseRuleId("094210", cmdContext)
	s.NoError(err, "Should parse rule ID with leading zeros without error")
	s.Equal("094210", cmdContext.Id, "Should preserve leading zeros in rule ID")
}

func (s *commonTestSuite) TestParseRuleIdWithLargeChainOffset() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with large chain offset (should fail because it's too large)
	err := ParseRuleId("942100-chain999", cmdContext)
	s.Error(err, "Should return error for chain offset larger than 255")
	s.Contains(err.Error(), "failed to match chain offset", "Error message should mention chain offset")
}

func (s *commonTestSuite) TestParseRuleIdWithSpecialCharacters() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with special characters in rule ID
	err := ParseRuleId("942@100", cmdContext)
	s.Error(err, "Should return error for rule ID with special characters")
}

func (s *commonTestSuite) TestParseRuleIdWithInvalidChainFormat() {
	cmdContext := NewCommandContext(s.outerContext, &s.logger)

	// Test with invalid chain format
	err := ParseRuleId("942100-chain", cmdContext)
	s.Error(err, "Should return error for invalid chain format")
}
