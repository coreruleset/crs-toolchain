// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type updateTestSuite struct {
	suite.Suite
}

func (suite *updateTestSuite) SetupTest() {
	rebuildUpdateCommand()
}

func TestRunUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(updateTestSuite))
}

func (s *updateTestSuite) TestUpdate_NormalRuleId() {
	rootCmd.SetArgs([]string{"regex", "update", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])

	allFlag, err := flags.GetBool("all")
	if s.NoError(err) {
		s.False(allFlag)
	}
}

func (s *updateTestSuite) TestUpdate_AllFlag() {
	rootCmd.SetArgs([]string{"regex", "update", "--all"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)

	allFlag, err := flags.GetBool("all")
	if s.NoError(err) {
		s.True(allFlag)
	}
}

func (s *updateTestSuite) TestUpdate_NoRuleIdNoAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "update"})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
}

func (s *updateTestSuite) TestUpdate_BothRuleIdAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "update", "123456", "--all"})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
}

func (s *updateTestSuite) TestUpdate_DashReturnsError() {
	rootCmd.SetArgs([]string{"regex", "update", "-"})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
}
