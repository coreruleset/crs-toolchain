// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
)

type updateTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	rulesDir   string
	cmdContext *regexInternal.CommandContext
	cmd        *cobra.Command
}

func (s *updateTestSuite) SetupTest() {
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

func TestRunUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(updateTestSuite))
}

func (s *updateTestSuite) TestUpdate_NormalRuleId() {
	s.writeDataFile("123456.ra", "", "")
	s.writeRuleFile("123456", `SecRule "@rx regex" \\`+"\nid:123456")
	s.cmd.SetArgs([]string{"123456"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.False(allFlag)
}

func (s *updateTestSuite) TestUpdate_MultipleRuleIds() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeDataFile("123457.ra", "", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"`)

	s.cmd.SetArgs([]string{"123456", "123457"})
	cmd, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 2)
	s.Equal("123456", args[0])
	s.Equal("123457", args[1])

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.False(allFlag)

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MultipleFilenames() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeDataFile("123457.ra", "", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"`)

	s.cmd.SetArgs([]string{"123456.ra", "123457.ra"})
	cmd, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 2)
	s.Equal("123456.ra", args[0])
	s.Equal("123457.ra", args[1])

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MixedRuleIdsAndFilenames() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeDataFile("123457.ra", "", "simpson")
	s.writeDataFile("123458.ra", "", "marge")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS "@rx regex3" \
	"id:123458"`)

	s.cmd.SetArgs([]string{"123456", "123457.ra", "123458"})
	cmd, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 3)
	s.Equal("123456", args[0])
	s.Equal("123457.ra", args[1])
	s.Equal("123458", args[2])

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"
SecRule ARGS "@rx marge" \
	"id:123458"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MultipleRuleIdsWithChains() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeDataFile("123456-chain1.ra", "", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx regex2" \`)

	s.cmd.SetArgs([]string{"123456", "123456-chain1"})
	cmd, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 2)
	s.Equal("123456", args[0])
	s.Equal("123456-chain1", args[1])

	expected := `SecRule ARGS "@rx homer" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx simpson" \`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_FilenameWithPath() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"`)

	// Pass a full path (as pre-commit would)
	fullPath := path.Join(s.dataDir, "123456.ra")
	s.cmd.SetArgs([]string{fullPath})
	cmd, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal(fullPath, args[0])

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_NonExistentFile() {
	s.cmd.SetArgs([]string{"999999.ra"})
	_, err := s.cmd.ExecuteC()

	s.Error(err)
	s.Contains(err.Error(), "file '999999.ra' not found in assembly directory")
}

func (s *updateTestSuite) TestUpdate_AllFlag() {
	s.cmd.SetArgs([]string{"--all"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.True(allFlag)
}

func (s *updateTestSuite) TestUpdate_NoRuleIdNoAllFlagReturnsError() {
	s.cmd.SetArgs([]string{})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID(s)/filename(s) or --all flag, found neither")
}

func (s *updateTestSuite) TestUpdate_BothRuleIdAndAllFlagReturnsError() {
	s.cmd.SetArgs([]string{"123456", "--all"})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID(s)/filename(s) or --all flag, found both")
}

func (s *updateTestSuite) TestUpdate_MultipleRuleIdsAndAllFlagReturnsError() {
	s.cmd.SetArgs([]string{"123456", "123457", "--all"})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID(s)/filename(s) or --all flag, found both")
}

func (s *updateTestSuite) TestUpdate_DashReturnsError() {
	s.cmd.SetArgs([]string{"-"})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "failed to match rule ID")
}

func (s *updateTestSuite) TestUpdate_InvalidRuleIdInMultipleReturnsError() {
	s.cmd.SetArgs([]string{"123456", "-", "123457"})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "failed to match rule ID")
}

func (s *updateTestSuite) TestUpdate_UpdatesAllWithAllFlag() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeDataFile("123457.ra", "", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`)
	s.cmd.SetArgs([]string{"--all"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_UpdateAllSkippingSubDirectories() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeDataFile("123457.ra", "include", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`)
	s.cmd.SetArgs([]string{"--all"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_UpdatesInverseRx() {
	s.writeDataFile("123456.ra", "", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "!@rx regex1" \
	"id:123456"`)
	s.cmd.SetArgs([]string{"--all"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := `SecRule ARGS "!@rx homer" \
	"id:123456"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_UpdatesChainedRule() {
	s.writeDataFile("123456-chain1.ra", "", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx regex2" \`)
	s.cmd.SetArgs([]string{"--all"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx homer" \`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) writeDataFile(filename string, directory string, contents string) {
	parentDirectory := s.dataDir
	if directory != "" {
		parentDirectory = path.Join(parentDirectory, directory)
		err := os.Mkdir(parentDirectory, fs.ModePerm)
		s.Require().NoError(err)

	}
	filePath := path.Join(parentDirectory, filename)
	err := os.WriteFile(filePath, []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *updateTestSuite) writeRuleFile(ruleId string, contents string) {
	prefix := ruleId[:3]
	fileName := fmt.Sprintf("prefix-%s-suffix.conf", prefix)
	err := os.WriteFile(path.Join(s.rulesDir, fileName), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *updateTestSuite) readRuleFile(ruleId string) string {
	prefix := ruleId[:3]
	fileName := fmt.Sprintf("prefix-%s-suffix.conf", prefix)
	contents, err := os.ReadFile(path.Join(s.rulesDir, fileName))
	s.Require().NoError(err)

	return string(contents)
}
