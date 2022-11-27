// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/util"
)

type renumberTestsTestSuite struct {
	suite.Suite
	tempDir  string
	testsDir string
}

func (s *renumberTestsTestSuite) writeTestFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.testsDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}

func (s *renumberTestsTestSuite) readTestFile(filename string) string {
	contents, err := os.ReadFile(path.Join(s.testsDir, filename))
	s.NoError(err)
	return string(contents)
}

func (s *renumberTestsTestSuite) captureStdout() *os.File {
	read, write, err := os.Pipe()
	s.NoError(err)

	realStdout := os.Stdout
	os.Stdout = write
	s.T().Cleanup(func() {
		os.Stdout = realStdout
	})
	return read
}

func (s *renumberTestsTestSuite) SetupTest() {
	rebuildUtilCommand()
	rebuildRenumberTestsCommand()

	tempDir, err := os.MkdirTemp("", "renumber-tests-tests")
	s.NoError(err)
	s.tempDir = tempDir

	dataDir := path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(dataDir, fs.ModePerm)
	s.NoError(err)

	s.testsDir = path.Join(s.tempDir, "tests", "regression", "tests")
	err = os.MkdirAll(s.testsDir, fs.ModePerm)
	s.NoError(err)
}

func (s *renumberTestsTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunRenumberTestsTestSuite(t *testing.T) {
	suite.Run(t, new(renumberTestsTestSuite))
}

func (s *renumberTestsTestSuite) TestRenumberTests_WithYaml() {
	s.writeTestFile("123456.yaml", "test_title: homer")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	actual := s.readTestFile("123456.yaml")
	s.Equal("test_title: 123456-1\n", actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_WithYml() {
	s.writeTestFile("123456.yml", "test_title: homer")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	actual := s.readTestFile("123456.yml")
	s.Equal("test_title: 123456-1\n", actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_NormalRuleIdWith() {
	s.writeTestFile("123456.yaml", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("renumber-tests", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *renumberTestsTestSuite) TestRenumberTests_NoArgument() {
	rootCmd.SetArgs([]string{"util", "renumber-tests"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, or flag, found nothing")
}

func (s *renumberTestsTestSuite) TestRenumberTests_ArgumentAndAllFlag() {
	rootCmd.SetArgs([]string{"util", "renumber-tests", "123456", "--all"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, or flag, found multiple")
}

func (s *renumberTestsTestSuite) TestRenumberTests_Dash() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "invalid argument '-'")
}

func (s *renumberTestsTestSuite) TestRenumberTests_CheckOnly() {
	contents := "test_title: homer"
	s.writeTestFile("123456.yaml", contents)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-c", "123456"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "Tests are not properly numbered")

	actual := s.readTestFile("123456.yaml")
	s.Equal(contents, actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_GitHubOutput() {
	read := s.captureStdout()

	contents := "test_title: homer"
	s.writeTestFile("123456.yaml", contents)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-cao", "github"})
	_, err := rootCmd.ExecuteC()

	s.ErrorIs(err, &util.TestNumberingError{})

	buffer := make([]byte, 1024)
	_, err = read.Read(buffer)
	s.NoError(err)

	output := string(buffer)
	s.Contains(output, "::warning::Test file not properly numbered")
	s.Contains(output, "::error::")
	s.Contains(output, "Please run `crs-toolchain util renumber-tests --all`")
}
