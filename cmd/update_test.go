// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UpdateTestSuite struct {
	suite.Suite
}

func (suite *UpdateTestSuite) SetupTest() {
	rebuildUpdateCommand()
}

func TestRunUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(UpdateTestSuite))
}

func (s *UpdateTestSuite) TestUpdate_NormalRuleId() {
	rootCmd.SetArgs([]string{"regex", "update", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	assert.Equal(s.T(), "update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	assert.Len(s.T(), args, 1)
	assert.Equal(s.T(), "123456", args[0])

	allFlag, err := flags.GetBool("all")
	if assert.NoError(s.T(), err) {
		assert.False(s.T(), allFlag)
	}
}

func (s *UpdateTestSuite) TestUpdate_AllFlag() {
	rootCmd.SetArgs([]string{"regex", "update", "--all"})
	cmd, _ := rootCmd.ExecuteC()

	assert.Equal(s.T(), "update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	assert.Len(s.T(), args, 0)

	allFlag, err := flags.GetBool("all")
	if assert.NoError(s.T(), err) {
		assert.True(s.T(), allFlag)
	}
}

func (s *UpdateTestSuite) TestUpdate_NoRuleIdNoAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "update"})
	_, err := rootCmd.ExecuteC()

	assert.Error(s.T(), err)
}

func (s *UpdateTestSuite) TestUpdate_BothRuleIdAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"regex", "update", "123456", "--all"})
	_, err := rootCmd.ExecuteC()

	assert.Error(s.T(), err)
}

func (s *UpdateTestSuite) TestUpdate_DashReturnsError() {
	rootCmd.SetArgs([]string{"regex", "update", "-"})
	_, err := rootCmd.ExecuteC()

	assert.Error(s.T(), err)
}
