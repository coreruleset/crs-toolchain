// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package phpDictionaryGen

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type phpDictionaryGenCmdTestSuite struct {
	suite.Suite
	rootDir    string
	cmdContext *internal.CommandContext
	cmd        *cobra.Command
}

func (s *phpDictionaryGenCmdTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.cmdContext = internal.NewCommandContext(s.rootDir)
	s.cmd = New(s.cmdContext)
}

func TestRunPhpDictionaryGenCmdTestSuite(t *testing.T) {
	suite.Run(t, new(phpDictionaryGenCmdTestSuite))
}

func (s *phpDictionaryGenCmdTestSuite) TestCommandName() {
	s.Equal("php-dictionary-gen", s.cmd.Name())
}

func (s *phpDictionaryGenCmdTestSuite) TestCommandHasFrequencyLimitFlag() {
	flag := s.cmd.Flags().Lookup("frequency-limit")
	s.Require().NotNil(flag)
	s.Equal("90000", flag.DefValue)
}

func (s *phpDictionaryGenCmdTestSuite) TestCommandHasAgeLimitFlag() {
	flag := s.cmd.Flags().Lookup("age-limit")
	s.Require().NotNil(flag)
	s.Equal("30", flag.DefValue)
}

func (s *phpDictionaryGenCmdTestSuite) TestCommandHasPhpRepoFlag() {
	flag := s.cmd.Flags().Lookup("php-repo")
	s.Require().NotNil(flag)
	s.Equal("", flag.DefValue)
}

func (s *phpDictionaryGenCmdTestSuite) TestCommandHasFrequencyListFlag() {
	flag := s.cmd.Flags().Lookup("frequency-list")
	s.Require().NotNil(flag)
	s.Equal("", flag.DefValue)
}

func (s *phpDictionaryGenCmdTestSuite) TestCommandHasRulesFlag() {
	flag := s.cmd.Flags().Lookup("rules")
	s.Require().NotNil(flag)
}

func (s *phpDictionaryGenCmdTestSuite) TestNormalizeRules_CommaSeparated() {
	result := normalizeRules([]string{"933150,933151"})
	s.Equal([]string{"933150", "933151"}, result)
}

func (s *phpDictionaryGenCmdTestSuite) TestNormalizeRules_SpaceSeparated() {
	result := normalizeRules([]string{"933150", "933151"})
	s.Equal([]string{"933150", "933151"}, result)
}

func (s *phpDictionaryGenCmdTestSuite) TestValidateRules_ValidRules() {
	s.NoError(validateRules([]string{"933150"}))
	s.NoError(validateRules([]string{"933151"}))
	s.NoError(validateRules([]string{"933161"}))
	s.NoError(validateRules([]string{"933150", "933151", "933161"}))
}

func (s *phpDictionaryGenCmdTestSuite) TestValidateRules_InvalidRule() {
	err := validateRules([]string{"999999"})
	s.Error(err)
	s.Contains(err.Error(), "999999")
}

func (s *phpDictionaryGenCmdTestSuite) TestValidateRules_Empty() {
	s.NoError(validateRules([]string{}))
}
