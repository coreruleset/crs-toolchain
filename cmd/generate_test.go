// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"
)

type generateTestSuite struct {
	suite.Suite
	tempDir string
	dataDir string
}

func (s *generateTestSuite) SetupTest() {
	rebuildGenerateCommand()

	tempDir, err := os.MkdirTemp("", "generate-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "util", "regexp-assemble", "data")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.NoError(err)
}

func (s *generateTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunGenerateTestSuite(t *testing.T) {
	suite.Run(t, new(generateTestSuite))
}

func (s *generateTestSuite) TestGenerate_NormalRuleId() {
	s.writeDatafile("123456.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "123456"})
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "-"})
	_, err := rootCmd.ExecuteC()

	if s.NoError(err) {
		s.True(ruleValues.useStdin)
	}

}

func (s *generateTestSuite) writeDatafile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}
