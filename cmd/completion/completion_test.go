// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package completion

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

type completionTestSuite struct {
	suite.Suite
	cmd *cobra.Command
}

func (s *completionTestSuite) SetupSuite() {
	s.cmd = New()
}

func TestRunCompletionTestSuite(t *testing.T) {
	suite.Run(t, new(completionTestSuite))
}

func (s *completionTestSuite) TestCompletion_BashShell() {
	s.cmd.SetArgs([]string{"bash"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("completion", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("bash", args[0])
}
