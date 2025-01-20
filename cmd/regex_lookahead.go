// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"os"

	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var lookaheadCmd = createLookaheadCommand()

func init() {
	buildLookaheadCommand()
}

func createLookaheadCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "lookahead <string> <string> ...",
		Short: "Generate fairly equivalent negative lookahead regular expression",
		Long: `Generate fairly equivalent regular expression from a list of strings.
This command is mainly used as a helper tool to generate a possible regex without negative lookahead.
It prints the generated regular expression to stdout.
`,
		Args: cobra.MinimumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no argument provided")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			prefix := cmd.Flag("prefix").Value.String()
			suffix := cmd.Flag("suffix").Value.String()
			alternative := regex.NegativeLookahead(args, prefix, suffix)
			os.Stdout.WriteString(alternative)
		},
	}
}

func buildLookaheadCommand() {
	regexCmd.AddCommand(lookaheadCmd)
	lookaheadCmd.PersistentFlags().StringP("prefix", "p", "", `Prefix to add to the generated regular expression`)
	lookaheadCmd.PersistentFlags().StringP("suffix", "s", "", `Suffix to add to the generated regular expression`)
}

func rebuildLookaheadCommand() {
	if lookaheadCmd != nil {
		lookaheadCmd.Parent().RemoveCommand(lookaheadCmd)
	}

	lookaheadCmd = createLookaheadCommand()
	buildLookaheadCommand()
}
