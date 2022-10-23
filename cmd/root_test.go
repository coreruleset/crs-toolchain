package cmd

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RootTestSuite struct {
	suite.Suite
}

func (suite *RootTestSuite) SetupTest() {
	rebuildRootCommand()
	rebuildRegexCommand()
	zerolog.SetGlobalLevel(defaultLogLevel)
}

func TestRunRootTestSuite(t *testing.T) {
	suite.Run(t, new(RootTestSuite))
}

func (s *RootTestSuite) TestRoot_NoArguments() {
	rootCmd.SetArgs([]string{})
	cmd, err := rootCmd.ExecuteC()

	assert.Equal(s.T(), "crs-toolchain", cmd.Name())
	assert.NoError(s.T(), err)
}

func (s *RootTestSuite) TestRoot_LogLevelDefault() {
	rootCmd.SetArgs([]string{})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	assert.NotNil(s.T(), logLevelFlag)
	assert.False(s.T(), logLevelFlag.Changed)

	assert.Equal(s.T(), zerolog.ErrorLevel, zerolog.GlobalLevel())
}

func (s *RootTestSuite) TestRoot_LogLevelChanged() {
	rootCmd.SetArgs([]string{"--log-level", "debug", "regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	assert.NotNil(s.T(), logLevelFlag)
	assert.True(s.T(), logLevelFlag.Changed)

	assert.Equal(s.T(), zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *RootTestSuite) TestRoot_LogLevelInvalidShouldBeDefault() {
	rootCmd.SetArgs([]string{"--log-level", "bizarre", "regex", "compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	assert.NotNil(s.T(), logLevelFlag)
	assert.True(s.T(), logLevelFlag.Changed)

	assert.Equal(s.T(), zerolog.GlobalLevel(), zerolog.ErrorLevel)
}

func (s *RootTestSuite) TestRoot_LogLevelAllowedAnywhere() {
	rootCmd.SetArgs([]string{"regex", "compare", "--log-level", "debug", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	assert.NotNil(s.T(), logLevelFlag)
	assert.True(s.T(), logLevelFlag.Changed)

	assert.Equal(s.T(), zerolog.DebugLevel, zerolog.GlobalLevel())
}
