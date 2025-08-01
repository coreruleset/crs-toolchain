// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type fpFinderTest struct {
	suite.Suite
}

func (s *fpFinderTest) SetupTest() {
	rebuildFpFinderCommand()
}

func TestRunFpFinderTest(t *testing.T) {
	suite.Run(t, new(fpFinderTest))
}

func (s *fpFinderTest) TestNoArgument() {
	rootCmd.SetArgs([]string{"util", "fp-finder"})
	cmd, err := rootCmd.ExecuteC()
	s.Equal(err.Error(), "requires at least 1 arg(s), only received 0")

	s.Equal("fp-finder", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)
}
