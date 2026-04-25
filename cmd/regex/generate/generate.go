// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"errors"
	"io"
	"os"
	"path"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
	"github.com/coreruleset/crs-toolchain/v2/regex/operators"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

var logger = log.With().Str("component", "cmd.regex.generate").Logger()

func New(cmdContext *regexInternal.CommandContext) *cobra.Command {
	return &cobra.Command{
		Use:   "generate RULE_ID | -",
		Short: "Generate regular expression from a regex-assembly file",
		Long: `Generate regular expression from a regex-assembly file.
This command is mainly used for quick debugging.
It prints the generated regular expression to stdout.

RULE_ID is the ID of the rule, e.g., 932100, or the regex-assembly file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.

The special token '-' will cause the script to accept input
from stdin.`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no argument provided")
			}
			if args[0] == "-" {
				cmdContext.UseStdin = true
				return nil
			}
			err := regexInternal.ParseRuleId(args[0], cmdContext)
			if err != nil {
				cmd.PrintErrf("failed to parse the rule ID from the input '%s'\n", args[0])
				return err
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctxt := processors.NewContext(cmdContext.RootContext())
			assembler := operators.NewAssembler(ctxt)
			var input []byte
			var err error
			if cmdContext.UseStdin {
				logger.Trace().Msg("Reading from stdin")
				input, err = io.ReadAll(os.Stdin)
				if err != nil {
					logger.Fatal().Err(err).Msg("Failed to read from stdin")
				}
			} else {
				filePath := path.Join(ctxt.RootContext().AssemblyDir(), cmdContext.FileName)
				logger.Trace().Msgf("Reading from %s", filePath)
				input, err = os.ReadFile(filePath)
				if err != nil {
					logger.Fatal().Err(err).Msgf("Failed to read regex-assembly file %s", filePath)
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
