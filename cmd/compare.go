// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// compareCmd represents the compare command
var compareCmd = createCompareCommand()

func init() {
	buildCompareCommand()
}

func createCompareCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "compare [RULE_ID]",
		Short: "Compare generated regular expressions with the contents of associated rules",
		Long: `Compare generated regular expressions with the contents of associated
rules.
This command is mainly used for debugging.
It prints regular expressions in fixed sized chunks and detects the
first change.
You can use this command to quickly check whether any rules are out of
sync with their data file.

RULE_ID is the ID of the rule, e.g., 932100, or the data file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either RULE_ID or flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either RULE_ID of flag, found both")
			} else if len(args) == 1 && args[0] == "-" {
				return errors.New("invalid argument '-'")
			}

			return nil
		}),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("compare called")
		},
	}

}

func buildCompareCommand() {
	regexCmd.AddCommand(compareCmd)
	compareCmd.PersistentFlags().BoolP("all", "a", false, `Instead of supplying a rule_id, you can tell the script to
update all rules from their data files`)
}

func rebuildCompareCommand() {
	if compareCmd != nil {
		compareCmd.Parent().RemoveCommand(compareCmd)
	}

	compareCmd = createCompareCommand()
	buildCompareCommand()
}
