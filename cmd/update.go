// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/theseion/crs-toolchain/v2/regex/operators"
	"github.com/theseion/crs-toolchain/v2/regex/processors"
)

// updateCmd represents the update command
var updateCmd = createUpdateCommand()

func init() {
	buildUpdateCommand()
}

func createUpdateCommand() *cobra.Command {

	return &cobra.Command{
		Use:   "update [RULE_ID]",
		Short: "Update regular expressions in rule files",
		Long: `Update regular expressions in rule files.
This command will generate regulare expressions from the data
files and update the associated rule.

RULE_ID is the ID of the rule, e.g., 932100, or the data file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either RULE_ID or flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either RULE_ID or flag, found both")
			} else if len(args) == 1 && args[0] == "-" {
				return errors.New("invalid argument '-'")
			}

			return nil
		}),

		Run: func(cmd *cobra.Command, args []string) {
			ctxt := processors.NewContext(rootValues.workingDirectory.String())
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read value for 'all' flag")
			}
			performUpdate(processAll, ctxt)
		},
	}

}

func buildUpdateCommand() {
	regexCmd.AddCommand(updateCmd)
	updateCmd.PersistentFlags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
update all rules from their data files`)
}

func rebuildUpdateCommand() {
	if updateCmd != nil {
		updateCmd.Parent().RemoveCommand(updateCmd)
	}

	updateCmd = createUpdateCommand()
	buildUpdateCommand()
}

func performUpdate(processAll bool, ctx *processors.Context) {
	if processAll {
		err := filepath.WalkDir(ctx.RootContext().DataDir(), func(filePath string, dirEntry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				// fail
				return err
			}

			if path.Ext(dirEntry.Name()) == "data" {
				subs := ruleIdRegex.FindAllStringSubmatch(dirEntry.Name(), -1)
				if subs == nil {
					// continue
					return nil
				}

				id := subs[0][1]
				chainOffsetString := subs[0][2]

				chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
				if err != nil && len(chainOffsetString) > 0 {
					return errors.New("failed to match chain offset. Value must not be larger than 255")
				}
				regex := runAssemble(filePath, ctx)
				processRegex(id, uint8(chainOffset), regex, ctx)
				return nil
			}
			return nil
		})
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to perform rule update(s)")
		}
	} else {
		regex := runAssemble(path.Join(ctx.RootContext().DataDir(), ruleValues.fileName), ctx)
		processRegex(ruleValues.id, ruleValues.chainOffset, regex, ctx)
	}
}

func runAssemble(filePath string, ctx *processors.Context) string {
	// FIXME: duplicated in generate.go
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
	return assembly
}

func processRegex(ruleId string, chainOffset uint8, regex string, ctxt *processors.Context) {
	logger.Info().Msgf("Processing %s, chain offset %d", ruleId, chainOffset)

	rulePrefix := ruleId[:3]
	matches, err := filepath.Glob(fmt.Sprintf("%s/*-%s-*", ctxt.RootContext().RulesDir(), rulePrefix))
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to find rule file for rule id %s", ruleId)
	}
	if matches == nil || len(matches) > 1 {
		logger.Fatal().Msgf("Failed to find rule file for rule id %s", ruleId)
	}

	filePath := matches[0]
	logger.Debug().Msgf("Processing data file %s", filePath)

	updateRegex(filePath, ruleId, chainOffset, regex)
}

func updateRegex(filePath string, ruleId string, chainOffset uint8, regex string) {
	contents, err := os.ReadFile(filePath)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to read rule file %s", filePath)
	}

	lines := bytes.Split(contents, []byte("\n"))

	idRegex := regexp.MustCompile(fmt.Sprintf("id:%s", ruleId))
	index := 0
	var line []byte
	for index, line = range lines {
		if idRegex.Match(line) {
			break
		}
	}
	regexLine := lines[index-1]
	regexRegex := regexp.MustCompile(`(.*"@rx ).*(" \\)`)
	found := regexRegex.FindAllStringSubmatch(string(regexLine), -1)
	if len(found) == 0 {
		logger.Fatal().Msgf("Failed to find rule %s in %s", ruleId, filePath)
	}
	updatedLine := found[0][1] + regex + found[0][2]
	lines[index-1] = []byte(updatedLine)

	err = os.WriteFile(filePath, bytes.Join(lines, []byte("\n")), fs.ModePerm)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to write rule file %s", filePath)
	}
}
