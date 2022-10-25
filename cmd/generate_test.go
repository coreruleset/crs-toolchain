// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type generateTestSuite struct {
	suite.Suite
}

func (suite *generateTestSuite) SetupTest() {
	rebuildGenerateCommand()
}

func TestRunGenerateTestSuite(t *testing.T) {
	suite.Run(t, new(generateTestSuite))
}

func (s *generateTestSuite) TestGenerate_NormalRuleId() {
	rootCmd.SetArgs([]string{"regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("generate", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *generateTestSuite) TestGenerate_NoRuleId() {
	rootCmd.SetArgs([]string{"regex", "generate"})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
}

func (s *generateTestSuite) TestGenerate_Dash() {
	rootCmd.SetArgs([]string{"regex", "generate", "-"})
	_, err := rootCmd.ExecuteC()

	if s.NoError(err) {
		s.True(ruleValues.useStdin)
	}

}
