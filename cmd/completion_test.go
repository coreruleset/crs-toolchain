// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type completionTestSuite struct {
	suite.Suite
}

func (s *completionTestSuite) SetupTest() {
	rebuildCompletionCommand()
}

func TestRunCompletionTestSuite(t *testing.T) {
	suite.Run(t, new(completionTestSuite))
}

func (s *completionTestSuite) TestCompletion_BashShell() {
	rootCmd.SetArgs([]string{"completion", "bash"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("completion", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("bash", args[0])
}
