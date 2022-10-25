// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type compareTestSuite struct {
	suite.Suite
}

func (suite *compareTestSuite) SetupTest() {
	rebuildCompareCommand()
}

func TestRunCompareTestSuite(t *testing.T) {
	suite.Run(t, new(compareTestSuite))
}

func (s *compareTestSuite) TestCompare_NormalRuleId() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("compare", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])

	allFlag, err := flags.GetBool("all")
	if s.NoError(err) {
		s.False(allFlag)
	}
}

func (s *compareTestSuite) TestCompare_AllFlag() {
	rootCmd.SetArgs([]string{"regex", "compare", "--all"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("compare", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)

	allFlag, err := flags.GetBool("all")
	if s.NoError(err) {
		s.True(allFlag)
	}
}

func (s *compareTestSuite) TestCompare_NoRuleIdNoAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "compare"})
	_, err := rootCmd.ExecuteC()
	s.Error(err)
}

func (s *compareTestSuite) TestCompare_BothRuleIdAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456", "all"})
	_, err := rootCmd.ExecuteC()
	s.Error(err)
}

func (s *updateTestSuite) TestCompare_DashReturnsError() {
	rootCmd.SetArgs([]string{"regex", "compare", "-"})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
}
