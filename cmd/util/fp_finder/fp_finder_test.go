// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package fpFinder

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type fpFinderTestSuite struct {
	suite.Suite
	rootDir    string
	cmdContext *internal.CommandContext
	cmd        *cobra.Command
}

func (s *fpFinderTestSuite) SetupSuite() {
	s.rootDir = s.T().TempDir()
	s.cmdContext = internal.NewCommandContext(s.rootDir)
	s.cmd = New(s.cmdContext)
}

func TestRunFpFinderTest(t *testing.T) {
	suite.Run(t, new(fpFinderTestSuite))
}

func (s *fpFinderTestSuite) TestNoArgument() {
	s.cmd.SetArgs([]string{})
	cmd, err := s.cmd.ExecuteC()
	s.Equal("requires at least 1 arg(s), only received 0", err.Error())

	s.Equal("fp-finder", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)
}

func (s *fpFinderTestSuite) TestDash() {
	s.cmd.SetArgs([]string{"-"})
	_, err := s.cmd.ExecuteC()

	s.Require().NoError(err)
}
