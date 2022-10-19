package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update [RULE_ID]",
	Short: "Update regular expressions in rule files",
	Long: `Update regular expressions in rule files.
This command will generate regulare expressions from the data
files and update the associated rule.

RULE_ID is the ID of the rule, e.g., 932100, or the data file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
	Args:      cobra.MaximumNArgs(1),
	ValidArgs: []string{"ruleId"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("update called")
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.PersistentFlags().BoolP("all", "a", false, `Instead of supplying a rule_id, you can tell the script to
update all rules from their data files`)
}
