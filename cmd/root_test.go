// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type rootTestSuite struct {
	suite.Suite
	tempDir string
	dataDir string
}

func (suite *rootTestSuite) SetupTest() {
	rebuildRootCommand()
	rebuildRegexCommand()
	zerolog.SetGlobalLevel(defaultLogLevel)

	tempDir, err := os.MkdirTemp("", "root-tests")
	suite.NoError(err)
	suite.tempDir = tempDir

	suite.dataDir = path.Join(suite.tempDir, "util", "regexp-assemble", "data")
	err = os.MkdirAll(suite.dataDir, fs.ModePerm)
	suite.NoError(err)
}

func (suite *rootTestSuite) TearDownTest() {
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

	s.Equal(path.Clean(s.tempDir), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestRoot_RelativeWorkingDirectory() {
	rootCmd.SetArgs([]string{"-d", "../util", "regex", "compare", "123456"})
	cwd, err := os.Getwd()
	s.NoError(err)
	parentCwd := path.Dir(cwd)
	err = os.MkdirAll(path.Join(parentCwd, "util", "regexp-assemble", "data"), fs.ModePerm)
	s.NoError(err)
	defer os.RemoveAll(path.Join(parentCwd, "util"))

	cmd, _ := rootCmd.ExecuteC()

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)
	s.True(path.IsAbs(workingDirectoryFlag.Value.String()))

	s.Equal(path.Clean(parentCwd), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestFindRootDirectoryInRoot() {
	root, err := findRootDirectory(s.tempDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInUtil() {
	root, err := findRootDirectory(path.Join(s.tempDir, "util"))
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInData() {
	root, err := findRootDirectory(s.dataDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInInclude() {
	includeDir := path.Join(s.dataDir, "include")
	err := os.Mkdir(includeDir, fs.ModePerm)
	s.NoError(err)
	root, err := findRootDirectory(includeDir)
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryInRules() {
	err := os.Mkdir(path.Join(s.tempDir, "rules"), fs.ModePerm)
	s.NoError(err)

	root, err := findRootDirectory(path.Join(s.tempDir, "rules"))
	if s.NoError(err) {
		s.Equal(s.tempDir, root)
	}
}

func (s *rootTestSuite) TestFindRootDirectoryFails() {
	root, err := findRootDirectory(os.TempDir())
	if !s.Error(err) {
		s.T().Logf("Unexpectedly found root directory %s, started at %s", root, os.TempDir())
	}

}
