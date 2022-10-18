/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate RULE_ID|-",
	Short: "Generate regular expression from a data file",
	Long: `Generate regular expression from a data file.
This command is mainly used for quick debugging.
It prints the generated regular expression to stdout.

RULE_ID isi the ID of the rule, e.g., 932100, or the data file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.

The special token '-' will cause the script to accept input
from stdin.`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"ruleId"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("generate called")

		fmt.Printf("%v", args)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
