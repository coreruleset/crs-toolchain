// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type regexTestSuite struct {
	suite.Suite
}

func (suite *regexTestSuite) SetupTest() {
	rebuildRegexCommand()
	rebuildCompareCommand()
}

func TestRunRegexTestSuite(t *testing.T) {
	suite.Run(t, new(regexTestSuite))
}

func (s *regexTestSuite) TestRegex_ParseRuleId() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456.data", ruleValues.fileName)
	s.Equal(uint8(0), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndChainOffset() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456-chain19"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456-chain19.data", ruleValues.fileName)
	s.Equal(uint8(19), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndChainOffsetAndFileName() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456-chain255.data"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456-chain255.data", ruleValues.fileName)
	s.Equal(uint8(255), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndFileName() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456.data"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456.data", ruleValues.fileName)
	s.Equal(uint8(0), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}
