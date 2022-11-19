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

type renumberTestsTestSuite struct {
	suite.Suite
	tempDir  string
	testsDir string
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

func (s *renumberTestsTestSuite) TestRenumberTests() {
	contents := `---
	meta:
	  enabled: true
	  name: 123456.yaml
	tests:
	  - test_title: bapedibupi
		desc: "test 1"
	  - test_title: "pine apple"
		desc: "test 2"`
	expected := `---
	meta:
	  enabled: true
	  name: 123456.yaml
	tests:
	  - test_title: 123456-1
		desc: "test 1"
	  - test_title: 123456-2
		desc: "test 2"`
	filePath := path.Join(s.testsDir, "123456.yaml")
	err := os.WriteFile(filePath, []byte(contents), fs.ModePerm)
	s.NoError(err)

	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests"})
	cmd, err := rootCmd.ExecuteC()
	s.NoError(err)
	s.Equal("renumber-tests", cmd.Name())

	actualContents, err := os.ReadFile(filePath)
	s.NoError(err)

	s.Equal(expected, string(actualContents))
}
