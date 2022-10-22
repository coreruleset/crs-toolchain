// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type CompareTestSuite struct {
	suite.Suite
}

func (suite *CompareTestSuite) SetupTest() {
	rebuildCompareCommand()
}

func TestRunCompareTestSuite(t *testing.T) {
	suite.Run(t, new(CompareTestSuite))
}

func (s *CompareTestSuite) TestCompare_NormalRuleId() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	assert.Equal(s.T(), "compare", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	assert.Len(s.T(), args, 1)
	assert.Equal(s.T(), "123456", args[0])

	allFlag, err := flags.GetBool("all")
	if assert.NoError(s.T(), err) {
		assert.False(s.T(), allFlag)
	}
}

func (s *CompareTestSuite) TestCompare_AllFlag() {
	rootCmd.SetArgs([]string{"regex", "compare", "--all"})
	cmd, _ := rootCmd.ExecuteC()

	assert.Equal(s.T(), "compare", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	assert.Len(s.T(), args, 0)

	allFlag, err := flags.GetBool("all")
	if assert.NoError(s.T(), err) {
		assert.True(s.T(), allFlag)
	}
}

func (s *CompareTestSuite) TestCompare_NoRuleIdNoAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "compare"})
	_, err := rootCmd.ExecuteC()
	assert.Error(s.T(), err)
}

func (s *CompareTestSuite) TestCompare_BothRuleIdAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456", "all"})
	_, err := rootCmd.ExecuteC()
	assert.Error(s.T(), err)
}

func (s *UpdateTestSuite) TestCompare_DashReturnsError() {
	rootCmd.SetArgs([]string{"regex", "compare", "-"})
	_, err := rootCmd.ExecuteC()

	assert.Error(s.T(), err)
}
