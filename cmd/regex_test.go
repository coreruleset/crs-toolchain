package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RegexTestSuite struct {
	suite.Suite
}

func (suite *RegexTestSuite) SetupTest() {
	rebuildRegexCommand()
	rebuildCompareCommand()
}

func TestRunRegexTestSuite(t *testing.T) {
	suite.Run(t, new(RegexTestSuite))
}

func (s *RegexTestSuite) TestRegex_ParseRuleId() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456"})
	rootCmd.ExecuteC()

	assert.Equal(s.T(), "123456", ruleValues.id)
	assert.Equal(s.T(), "123456.data", ruleValues.fileName)
	assert.Equal(s.T(), uint8(0), ruleValues.chainOffset)
	assert.False(s.T(), ruleValues.useStdin)
}

func (s *RegexTestSuite) TestRegex_ParseRuleIdAndChainOffset() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456-chain19"})
	rootCmd.ExecuteC()

	assert.Equal(s.T(), "123456", ruleValues.id)
	assert.Equal(s.T(), "123456-chain19.data", ruleValues.fileName)
	assert.Equal(s.T(), uint8(19), ruleValues.chainOffset)
	assert.False(s.T(), ruleValues.useStdin)
}

func (s *RegexTestSuite) TestRegex_ParseRuleIdAndChainOffsetAndFileName() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456-chain255.data"})
	rootCmd.ExecuteC()

	assert.Equal(s.T(), "123456", ruleValues.id)
	assert.Equal(s.T(), "123456-chain255.data", ruleValues.fileName)
	assert.Equal(s.T(), uint8(255), ruleValues.chainOffset)
	assert.False(s.T(), ruleValues.useStdin)
}

func (s *RegexTestSuite) TestRegex_ParseRuleIdAndFileName() {
	rootCmd.SetArgs([]string{"regex", "compare", "123456.data"})
	rootCmd.ExecuteC()

	assert.Equal(s.T(), "123456", ruleValues.id)
	assert.Equal(s.T(), "123456.data", ruleValues.fileName)
	assert.Equal(s.T(), uint8(0), ruleValues.chainOffset)
	assert.False(s.T(), ruleValues.useStdin)
}
