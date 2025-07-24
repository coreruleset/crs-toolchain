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
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.rulesDir = path.Join(s.tempDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.Require().NoError(err)
}

func (s *updateTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestRunUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(updateTestSuite))
}

func (s *updateTestSuite) TestUpdate_NormalRuleId() {
	s.writeDataFile("123456.ra", "")
	s.writeRuleFile("123456", `SecRule "@rx regex" \\`+"\nid:123456")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456"})
	cmd, _ := rootCmd.ExecuteC()

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
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123457.ra", "simpson")
	// Both rules go in the same file since they share the same prefix (123)
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"`)
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "123457"})
	cmd, err := rootCmd.ExecuteC()
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

	// Verify both rules were updated
	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MultipleFilenames() {
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123457.ra", "simpson")
	// Both rules go in the same file since they share the same prefix (123)
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"`)
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456.ra", "123457.ra"})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 2)
	s.Equal("123456.ra", args[0])
	s.Equal("123457.ra", args[1])

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.False(allFlag)

	// Verify both rules were updated
	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MixedRuleIdsAndFilenames() {
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123457.ra", "simpson")
	s.writeDataFile("123458.ra", "marge")
	// All rules go in the same file since they share the same prefix (123)
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS "@rx regex3" \
	"id:123458"`)
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "123457.ra", "123458"})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 3)
	s.Equal("123456", args[0])
	s.Equal("123457.ra", args[1])
	s.Equal("123458", args[2])

	// Verify all rules were updated
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
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123456-chain1.ra", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx regex2" \`)
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "123456-chain1"})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 2)
	s.Equal("123456", args[0])
	s.Equal("123456-chain1", args[1])

	// Verify both the main rule and chained rule were updated
	expected := `SecRule ARGS "@rx homer" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx simpson" \`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_ChainedRuleWithFilename() {
	s.writeDataFile("123456-chain1.ra", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx regex2" \`)
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456-chain1.ra"})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal("123456-chain1.ra", args[0])

	// Verify the chained rule was updated
	expected := `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx simpson" \`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_NonExistentFile() {
	// Don't create the file - that's the point of this test
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "999999.ra"})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
	s.Contains(err.Error(), "file '999999.ra' not found in assembly directory")
}

func (s *updateTestSuite) TestUpdate_InvalidFilename() {
	// Use a filename that doesn't match the rule ID pattern
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "invalid-filename.ra"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "failed to match rule ID")
}

func (s *updateTestSuite) TestUpdate_RelativePath() {
	s.writeDataFile("123456.ra", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"`)
	
	// Create a file at a relative path (simulating pre-commit scenario)
	relativeDir := path.Join(s.tempDir, "regex-assembly")
	relativePath := path.Join(relativeDir, "123456.ra")
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", relativePath})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal(relativePath, args[0])

	// Verify the rule was updated
	expected := `SecRule ARGS "@rx homer" \
	"id:123456"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MultipleRelativePaths() {
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123457.ra", "simpson")
	// Both rules go in the same file since they share the same prefix (123)
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"`)
	
	// Create files at relative paths
	relativeDir := path.Join(s.tempDir, "regex-assembly")
	relativePath1 := path.Join(relativeDir, "123456.ra")
	relativePath2 := path.Join(relativeDir, "123457.ra")
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", relativePath1, relativePath2})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 2)
	s.Equal(relativePath1, args[0])
	s.Equal(relativePath2, args[1])

	// Verify both rules were updated
	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_MixedRelativePathsAndRuleIds() {
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123457.ra", "simpson")
	s.writeDataFile("123458.ra", "marge")
	// All rules go in the same file since they share the same prefix (123)
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS "@rx regex3" \
	"id:123458"`)
	
	// Mix relative paths with RULE_IDs
	relativeDir := path.Join(s.tempDir, "regex-assembly")
	relativePath := path.Join(relativeDir, "123456.ra")
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", relativePath, "123457", "123458.ra"})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 3)
	s.Equal(relativePath, args[0])
	s.Equal("123457", args[1])
	s.Equal("123458.ra", args[2])

	// Verify all rules were updated
	expected := `SecRule ARGS "@rx homer" \
	"id:123456"
SecRule ARGS "@rx simpson" \
	"id:123457"
SecRule ARGS "@rx marge" \
	"id:123458"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_RelativePathChainedRule() {
	s.writeDataFile("123456-chain1.ra", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx regex2" \`)
	
	// Use relative path for chained rule
	relativeDir := path.Join(s.tempDir, "regex-assembly")
	relativePath := path.Join(relativeDir, "123456-chain1.ra")
	
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", relativePath})
	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 1)
	s.Equal(relativePath, args[0])

	// Verify the chained rule was updated
	expected := `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx simpson" \`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_NonExistentRelativePath() {
	nonExistentPath := path.Join(s.tempDir, "nonexistent", "999999.ra")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", nonExistentPath})
	_, err := rootCmd.ExecuteC()

	s.Error(err)
	s.Contains(err.Error(), "file '999999.ra' not found in assembly directory or at relative path")
}

func (s *updateTestSuite) TestUpdate_AllFlag() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("update", cmd.Name())

	flags := cmd.Flags()
	args := flags.Args()
	s.Len(args, 0)

	allFlag, err := flags.GetBool("all")
	s.Require().NoError(err)
	s.True(allFlag)
}

func (s *updateTestSuite) TestUpdate_NoRuleIdNoAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID(s)/filename(s) or --all flag, found neither")
}

func (s *updateTestSuite) TestUpdate_BothRuleIdAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "--all"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID(s)/filename(s) or --all flag, found both")
}

func (s *updateTestSuite) TestUpdate_MultipleRuleIdsAndAllFlagReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "123457", "--all"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected either RULE_ID(s)/filename(s) or --all flag, found both")
}

func (s *updateTestSuite) TestUpdate_DashReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "-"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "failed to match rule ID")
}

func (s *updateTestSuite) TestUpdate_InvalidRuleIdInMultipleReturnsError() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "123456", "-", "123457"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "failed to match rule ID")
}

func (s *updateTestSuite) TestUpdate_UpdatesAllWithAllFlag() {
	s.writeDataFile("123456.ra", "homer")
	s.writeDataFile("123457.ra", "simpson")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456"
SecRule ARGS "@rx regex2" \
	"id:123457"
SecRule ARGS '@rx regex3" \
	"id:123458"`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
	_, err := rootCmd.ExecuteC()
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

func (s *updateTestSuite) TestUpdate_UpdatesInverseRx() {
	s.writeDataFile("123456.ra", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "!@rx regex1" \
	"id:123456"`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := `SecRule ARGS "!@rx homer" \
	"id:123456"`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) TestUpdate_UpdatesChainedRule() {
	s.writeDataFile("123456-chain1.ra", "homer")
	s.writeRuleFile("123456", `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx regex2" \`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "update", "--all"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := `SecRule ARGS "@rx regex1" \
	"id:123456, \
	chain"
		SecRule ARGS "@rx homer" \`
	actual := s.readRuleFile("123456")
	s.Equal(expected, actual)
}

func (s *updateTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
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
