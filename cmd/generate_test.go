package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type GenerateTestSuite struct {
	suite.Suite
}

func (suite *GenerateTestSuite) SetupTest() {
	rebuildGenerateCommand()
}

func TestRunGenerateTestSuite(t *testing.T) {
	suite.Run(t, new(GenerateTestSuite))
}

func (s *GenerateTestSuite) TestGenerate_NormalRuleId() {
	rootCmd.SetArgs([]string{"regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	assert.Equal(s.T(), "generate", cmd.Name())

	args := cmd.Flags().Args()
	assert.Len(s.T(), args, 1)
	assert.Equal(s.T(), "123456", args[0])
}

func (s *GenerateTestSuite) TestGenerate_NoRuleId() {
	rootCmd.SetArgs([]string{"regex", "generate"})
	_, err := rootCmd.ExecuteC()

	assert.Error(s.T(), err)
}

func (s *GenerateTestSuite) TestGenerate_Dash() {
	rootCmd.SetArgs([]string{"regex", "generate", "-"})
	_, err := rootCmd.ExecuteC()

	if assert.NoError(s.T(), err) {
		assert.True(s.T(), ruleValues.useStdin)
	}

}
