package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalRuleId(t *testing.T) {
	rootCmd.SetArgs([]string{"compare", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	assert.Equal(t, "compare", cmd.Name())

	args := cmd.Flags().Args()
	assert.Len(t, args, 1)
	assert.Equal(t, "123456", args[0])
}

func TestNoRuleId(t *testing.T) {
	rootCmd.SetArgs([]string{"compare"})
	_, err := rootCmd.ExecuteC()

	assert.Error(t, err)
}
