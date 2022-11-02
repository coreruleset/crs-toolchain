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

type regexTestSuite struct {
	suite.Suite
	tempDir  string
	dataDir  string
	rulesDir string
}

func (s *regexTestSuite) SetupTest() {
	rebuildRegexCommand()
	rebuildCompareCommand()

	tempDir, err := os.MkdirTemp("", "regex-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "util", "regexp-assemble", "data")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.NoError(err)

	s.rulesDir = path.Join(s.tempDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.NoError(err)
}

func (s *regexTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunRegexTestSuite(t *testing.T) {
	suite.Run(t, new(regexTestSuite))
}

func (s *regexTestSuite) TestRegex_ParseRuleId() {
	s.writeDataFile("123456.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "123456"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456.data", ruleValues.fileName)
	s.Equal(uint8(0), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndChainOffset() {
	s.writeDataFile("123456-chain19.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "123456-chain19"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456-chain19.data", ruleValues.fileName)
	s.Equal(uint8(19), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndChainOffsetAndFileName() {
	s.writeDataFile("123456-chain255.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "123456-chain255.data"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456-chain255.data", ruleValues.fileName)
	s.Equal(uint8(255), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndFileName() {
	s.writeDataFile("123456.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "123456.data"})
	_, err := rootCmd.ExecuteC()

	s.NoError(err, "failed to execute rootCmd")
	s.Equal("123456", ruleValues.id)
	s.Equal("123456.data", ruleValues.fileName)
	s.Equal(uint8(0), ruleValues.chainOffset)
	s.False(ruleValues.useStdin)
}

func (s *regexTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}
