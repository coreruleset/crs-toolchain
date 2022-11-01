// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type rootTestSuite struct {
	suite.Suite
	tempDir string
}

func (suite *rootTestSuite) SetupTest() {
	rebuildRootCommand()
	rebuildRegexCommand()
	zerolog.SetGlobalLevel(defaultLogLevel)

	tempDir, err := os.MkdirTemp("", "root-tests")
	suite.NoError(err)
	suite.tempDir = tempDir
}

func (suite *rootTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func TestRunRootTestSuite(t *testing.T) {
	suite.Run(t, new(rootTestSuite))
}

func (s *rootTestSuite) TestRoot_NoArguments() {
	rootCmd.SetArgs([]string{})
	cmd, err := rootCmd.ExecuteC()

	s.Equal("crs-toolchain", cmd.Name())
	s.NoError(err)
}

func (s *rootTestSuite) TestRoot_LogLevelDefault() {
	rootCmd.SetArgs([]string{})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.False(logLevelFlag.Changed)

	s.Equal(zerolog.ErrorLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_LogLevelChanged() {
	rootCmd.SetArgs([]string{"--log-level", "debug", "regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_LogLevelInvalidShouldBeDefault() {
	rootCmd.SetArgs([]string{"--log-level", "bizarre", "regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.GlobalLevel(), zerolog.ErrorLevel)
}

func (s *rootTestSuite) TestRoot_LogLevelAllowedAnywhere() {
	rootCmd.SetArgs([]string{"regex", "compare", "--log-level", "debug", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_AbsoluteWorkingDirectory() {
	rootCmd.SetArgs([]string{"--directory", os.TempDir(), "regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)

	s.Equal(path.Clean(os.TempDir()), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestRoot_RelativeWorkingDirectory() {
	rootCmd.SetArgs([]string{"-d", "../homer", "regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)
	s.True(path.IsAbs(workingDirectoryFlag.Value.String()))

	cwd, err := os.Getwd()
	s.NoError(err)
	parentDir := path.Dir(cwd)
	expectedPath := path.Join(parentDir, "homer")

	s.Equal(path.Clean(expectedPath), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestFindRootDirectoryInRoot() {
	err := os.MkdirAll(path.Join(s.tempDir, "util", "data", "include"), 0777)
	s.NoError(err)

	os.Setenv("PWD", s.tempDir)
	root, err := findRootDirectory(s.tempDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInUtil() {
	err := os.MkdirAll(path.Join(s.tempDir, "util", "data", "include"), 0777)
	s.NoError(err)

	os.Setenv("PWD", path.Join(s.tempDir, "util"))
	root, err := findRootDirectory(s.tempDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInData() {
	err := os.MkdirAll(path.Join(s.tempDir, "util", "data", "include"), 0777)
	s.NoError(err)

	os.Setenv("PWD", path.Join(s.tempDir, "util", "data"))
	root, err := findRootDirectory(s.tempDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInInclude() {
	err := os.MkdirAll(path.Join(s.tempDir, "util", "data", "include"), 0777)
	s.NoError(err)

	os.Setenv("PWD", path.Join(s.tempDir, "util", "data", "include"))
	root, err := findRootDirectory(s.tempDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInRules() {
	err := os.MkdirAll(path.Join(s.tempDir, "util", "data", "include"), 0777)
	s.NoError(err)
	err = os.Mkdir(path.Join(s.tempDir, "rules"), 0777)
	s.NoError(err)

	os.Setenv("PWD", path.Join(s.tempDir, "rules"))
	root, err := findRootDirectory(s.tempDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryFails() {
	err := os.MkdirAll(path.Join(s.tempDir, "util", "data"), 0777)
	s.NoError(err)

	os.Setenv("PWD", path.Join(s.tempDir))
	_, err = findRootDirectory(s.tempDir)
	s.Error(err)
}
