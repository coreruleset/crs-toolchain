// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
)

type generateTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	cmdContext *regexInternal.CommandContext
	cmd        *cobra.Command
}

func (s *generateTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err := os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)
	rootCtx := internal.NewCommandContext(s.rootDir)
	s.cmdContext = regexInternal.NewCommandContext(rootCtx, &logger)
	s.cmd = New(s.cmdContext)
}

func TestRunGenerateTestSuite(t *testing.T) {
	suite.Run(t, new(generateTestSuite))
}

func (s *generateTestSuite) TestGenerate_NormalRuleId() {
	s.writeDatafile("123456.ra", "")
	s.cmd.SetArgs([]string{"123456"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("generate", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *generateTestSuite) TestGenerate_NoRuleId() {
	s.cmd.SetArgs([]string{})
	_, err := s.cmd.ExecuteC()

	s.Error(err)
}

func (s *generateTestSuite) TestGenerate_Dash() {
	s.cmd.SetArgs([]string{"-"})
	_, err := s.cmd.ExecuteC()

	s.Require().NoError(err)
	s.True(s.cmdContext.UseStdin)
}

func (s *generateTestSuite) writeDatafile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}
