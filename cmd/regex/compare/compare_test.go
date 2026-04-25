// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package compare

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
)

type compareTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	rulesDir   string
	cmdContext *regexInternal.CommandContext
	cmd        *cobra.Command
}

func (s *compareTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *compareTestSuite) writeRuleFile(ruleId string, contents string) {
	prefix := ruleId[:3]
	fileName := fmt.Sprintf("prefix-%s-suffix.conf", prefix)
	err := os.WriteFile(path.Join(s.rulesDir, fileName), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *compareTestSuite) captureStdout() *os.File {
	read, write, err := os.Pipe()
	s.Require().NoError(err)

	realStdout := os.Stdout
	os.Stdout = write
	s.T().Cleanup(func() {
		os.Stdout = realStdout
	})
	return read
}

func (s *compareTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err := os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.rulesDir = path.Join(s.rootDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := internal.NewCommandContext(s.rootDir)
	s.cmdContext = regexInternal.NewCommandContext(rootContext, &logger)
	s.cmd = New(s.cmdContext)
}

func TestRunCompareTestSuite(t *testing.T) {
	suite.Run(t, new(compareTestSuite))
}

func (s *compareTestSuite) TestCompare_NormalRuleId() {
	s.writeDataFile("123456.ra", "")
	s.writeRuleFile("123456", `SecRule... "@rx regex" \\`+"\nid:123456")
	s.cmd.SetArgs([]string{"123456"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("compare", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.False(allFlag)
}

func (s *compareTestSuite) TestCompare_AllFlag() {
	s.writeRuleFile("123456",
		`SecRule... "@rx oldfoo" \
id:123456
SecRule... "@rx oldbar" \
id:123457`)
	s.writeDataFile("123456.ra", "foo")
	s.writeDataFile("123457.ra", "bar")
	s.cmd.SetArgs([]string{"--all"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("compare", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.True(allFlag)
}

func (s *compareTestSuite) TestCompare_NoRuleIdNoAllFlagReturnsError() {
	s.cmd.SetArgs([]string{})
	_, err := s.cmd.ExecuteC()
	s.EqualError(err, "expected either RULE_ID or flag, found neither")
}

func (s *compareTestSuite) TestCompare_BothRuleIdAndAllFlagReturnsError() {
	s.cmd.SetArgs([]string{"123456", "--all"})
	_, err := s.cmd.ExecuteC()
	s.EqualError(err, "expected either RULE_ID or flag, found both")
}

func (s *compareTestSuite) TestCompare_NoChange() {
	read := s.captureStdout()

	s.writeRuleFile("123456", `SecRule... "@rx foo" \
id:123456`)
	s.writeDataFile("123456.ra", "foo")
	s.cmd.SetArgs([]string{"--all"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	buffer := make([]byte, 1024)
	_, err = read.Read(buffer)
	s.Require().NoError(err)

	output := strings.Split(string(buffer), "\n")
	s.Len(output, 2)
	s.Equal("Regex of 123456 has not changed", output[0])
}

func (s *compareTestSuite) TestCompare_Change() {
	read := s.captureStdout()

	s.writeRuleFile("123456", `SecRule... "@rx oldfoo" \
id:123456`)
	s.writeDataFile("123456.ra", "foo")
	s.cmd.SetArgs([]string{"--all"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	buffer := make([]byte, 1024)
	_, err = read.Read(buffer)
	s.Require().NoError(err)

	output := strings.Split(string(buffer), "\n")
	s.Len(output, 5)
	s.Equal("Regex of 123456 has changed!", output[0])
}
