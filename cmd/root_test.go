// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	loggerConfig "github.com/coreruleset/crs-toolchain/v2/logger"
)

type rootTestSuite struct {
	suite.Suite
	rootDir string
	dataDir string
}

func (s *rootTestSuite) SetupTest() {
	zerolog.SetGlobalLevel(loggerConfig.DefaultLogLevel)

	s.rootDir = s.T().TempDir()
	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err := os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)
}

func TestRunRootTestSuite(t *testing.T) {
	suite.Run(t, new(rootTestSuite))
}

func (s *rootTestSuite) TestRoot_NoArguments() {
	rootCmd := New()
	rootCmd.SetArgs([]string{})
	cmd, err := rootCmd.ExecuteC()

	s.Equal("crs-toolchain", cmd.Name())
	s.Require().NoError(err)
}

func (s *rootTestSuite) TestRoot_LogLevelDefault() {
	rootCmd := New()
	rootCmd.SetArgs([]string{})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.False(logLevelFlag.Changed)

	s.Equal(loggerConfig.DefaultLogLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_LogLevelChanged() {
	s.writeDataFile("123456.ra", "")
	rootCmd := New()
	rootCmd.SetArgs([]string{"-d", s.rootDir, "--log-level", "debug", "regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_LogLevelInvalidShouldBeDefault() {
	s.writeDataFile("123456.ra", "")
	rootCmd := New()
	rootCmd.SetArgs([]string{"-d", s.rootDir, "--log-level", "bizarre", "regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	// Will not be set if invalid
	s.False(logLevelFlag.Changed)

	s.Equal(zerolog.GlobalLevel(), loggerConfig.DefaultLogLevel)
}

func (s *rootTestSuite) TestRoot_LogLevelAllowedAnywhere() {
	s.writeDataFile("123456.ra", "")
	rootCmd := New()
	rootCmd.SetArgs([]string{"-d", s.rootDir, "regex", "generate", "--log-level", "debug", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_AbsoluteWorkingDirectory() {
	s.writeDataFile("123456.ra", "")
	rootCmd := New()
	rootCmd.SetArgs([]string{"--directory", s.rootDir, "regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)

	s.Equal(path.Clean(s.rootDir), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestRoot_RelativeWorkingDirectory() {
	rootCmd := New()
	rootCmd.SetArgs([]string{"-d", "../testDir", "regex", "generate", "-"})
	cwd, err := os.Getwd()
	s.Require().NoError(err)
	parentCwd := path.Dir(cwd)
	err = os.MkdirAll(path.Join(parentCwd, "testDir", "regex-assembly"), fs.ModePerm)
	s.Require().NoError(err)
	defer os.RemoveAll(path.Join(parentCwd, "testDir"))

	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)
	s.True(path.IsAbs(workingDirectoryFlag.Value.String()))

	s.Equal(path.Join(parentCwd, "testDir"), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestFindRootDirectoryInRoot() {
	cmdContext := internal.NewCommandContext(s.rootDir)
	flag := &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}
	err := flag.Set(s.rootDir)
	s.Require().NoError(err)
	s.Equal(s.rootDir, cmdContext.WorkingDirectory)
}

func (s *rootTestSuite) TestFindRootDirectoryInUtil() {
	cmdContext := internal.NewCommandContext(s.rootDir)
	flag := &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}
	err := flag.Set(path.Join(s.rootDir, "util"))
	s.Require().NoError(err)
	s.Equal(s.rootDir, cmdContext.WorkingDirectory)
}

func (s *rootTestSuite) TestFindRootDirectoryInData() {
	cmdContext := internal.NewCommandContext(s.rootDir)
	flag := &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}
	err := flag.Set(s.dataDir)
	s.Require().NoError(err)
	s.Equal(s.rootDir, cmdContext.WorkingDirectory)
}

func (s *rootTestSuite) TestFindRootDirectoryInInclude() {
	includeDir := path.Join(s.dataDir, "include")
	err := os.Mkdir(includeDir, fs.ModePerm)
	s.Require().NoError(err)

	cmdContext := internal.NewCommandContext(s.rootDir)
	flag := &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}
	err = flag.Set(includeDir)
	s.Require().NoError(err)
	s.Equal(s.rootDir, cmdContext.WorkingDirectory)
}

func (s *rootTestSuite) TestFindRootDirectoryInRules() {
	rulesDir := path.Join(s.rootDir, "rules")
	err := os.Mkdir(rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	cmdContext := internal.NewCommandContext(s.rootDir)
	flag := &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}
	err = flag.Set(rulesDir)
	s.Require().NoError(err)
	s.Equal(s.rootDir, cmdContext.WorkingDirectory)
}

func (s *rootTestSuite) TestFindRootDirectoryFails() {
	cmdContext := internal.NewCommandContext(s.rootDir)
	flag := &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}
	err := flag.Set(filepath.Dir(s.rootDir))
	s.Error(err)
}

func (s *rootTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}
