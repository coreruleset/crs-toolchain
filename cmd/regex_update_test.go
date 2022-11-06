// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"
)

type updateTestSuite struct {
	suite.Suite
	tempDir  string
	dataDir  string
	rulesDir string
}

func (s *updateTestSuite) SetupTest() {
	rebuildUpdateCommand()

	tempDir, err := os.MkdirTemp("", "update-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "util", "regexp-assemble", "data")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.NoError(err)

	s.rulesDir = path.Join(s.tempDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.NoError(err)
}

func (s *updateTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(updateTestSuite))
}

func (s *updateTestSuite) TestUpdate_NormalRuleId() {
	s.writeDataFile("123456.data", "")
	s.writeRuleFile("123456", `SecRule "@rx regex" \\`+"\nid:123456")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456"})
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID or flag, found neither")
}

func (s *updateTestSuite) TestUpdate_BothRuleIdAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "--all"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID or flag, found both")
}

func (s *updateTestSuite) TestUpdate_DashReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "-"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "failed to match rule ID")
}

func (s *updateTestSuite) TestUpdate_UpdatesAllWithAllFlag() {
	s.writeDataFile("123456.data", "homer")
	s.writeDataFile("123457.data", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_UpdatesInverseRx() {
	s.writeDataFile("123456.data", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "!@rx regex1" \
	"id:123456"`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `SecRule ARGS "!@rx homer" \
	"id:123456"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}

func (s *updateTestSuite) writeRuleFile(ruleId string, contents string) {
	prefix := ruleId[:3]
	fileName := fmt.Sprintf("prefix-%s-suffix.conf", prefix)
	err := os.WriteFile(path.Join(s.rulesDir, fileName), []byte(contents), fs.ModePerm)
	s.NoError(err)
}

func (s *updateTestSuite) readRuleFile(ruleId string) string {
	prefix := ruleId[:3]
	fileName := fmt.Sprintf("prefix-%s-suffix.conf", prefix)
	contents, err := os.ReadFile(path.Join(s.rulesDir, fileName))
	s.NoError(err)

	return string(contents)
}
