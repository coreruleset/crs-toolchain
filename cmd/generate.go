// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io"
	"os"
	"path"

	"github.com/spf13/cobra"

	"github.com/theseion/crs-toolchain/v2/regex/operators"
	"github.com/theseion/crs-toolchain/v2/regex/processors"
)

// generateCmd represents the generate command
var generateCmd = createGenerateCommand()

func init() {
	buildGenerateCommand()
}

func createGenerateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "generate RULE_ID | -",
		Short: "Generate regular expression from a data file",
		Long: `Generate regular expression from a data file.
This command is mainly used for quick debugging.
It prints the generated regular expression to stdout.

RULE_ID is the ID of the rule, e.g., 932100, or the data file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.

The special token '-' will cause the script to accept input
from stdin.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctxt := processors.NewContext(rootValues.workingDirectory.String())
			assembler := operators.NewAssembler(ctxt)
			var input []byte
			var err error
			if ruleValues.useStdin {
				logger.Trace().Msg("Reading from stdin")
				input, err = io.ReadAll(os.Stdin)
				if err != nil {
					logger.Fatal().Err(err).Msg("Failed to read from stdin")
				}
			} else {
				filePath := path.Join(ctxt.RootContext().DataDir(), ruleValues.fileName)
				logger.Trace().Msgf("Reading from %s", filePath)
				input, err = os.ReadFile(filePath)
				if err != nil {
					logger.Fatal().Err(err).Msgf("Failed to read data file %s", filePath)
				}
			}
			assembly, err := assembler.Run(string(input))
			if err != nil {
				logger.Fatal().Err(err).Send()
			}
			os.Stdout.WriteString(assembly)
		},
	}
}

func buildGenerateCommand() {
	regexCmd.AddCommand(generateCmd)
}

func rebuildGenerateCommand() {
	if generateCmd != nil {
		generateCmd.Parent().RemoveCommand(generateCmd)
	}

	generateCmd = createGenerateCommand()
	buildGenerateCommand()
}
