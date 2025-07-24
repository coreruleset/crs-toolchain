// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
	"github.com/coreruleset/crs-toolchain/v2/utils"
)

const maxGroupSplittingDepth = 2

type ComparisonError struct {
}

func (n *ComparisonError) Error() string {
	return "regular expressions did not match"
}

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
sync with their regex-assembly file.

RULE_ID is the ID of the rule, e.g., 932100, or the regex-assembly file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either RULE_ID or flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either RULE_ID or flag, found both")
			}
			return nil
		}),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			err := parseRuleId(args[0])
			if err != nil {
				cmd.PrintErrf("failed to parse the rule ID from the input '%s'\n", args[0])
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			ctxt := processors.NewContext(rootContext)
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Error().Err(err).Msg("Failed to read value for 'all' flag")
				return err
			}

			// Start running. If an error occurs, propagate but don't print anything
			// command related.
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return performCompare(processAll, ctxt)
		},
	}

}

func buildCompareCommand() {
	regexCmd.AddCommand(compareCmd)
	compareCmd.Flags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
compare all rules from their regex-assembly files`)
}

func rebuildCompareCommand() {
	if compareCmd != nil {
		compareCmd.Parent().RemoveCommand(compareCmd)
	}

	compareCmd = createCompareCommand()
	buildCompareCommand()
}

// FIXME: duplicated in update.go
func performCompare(processAll bool, ctx *processors.Context) error {
	failed := false
	if processAll {
		err := filepath.WalkDir(ctx.RootContext().AssemblyDir(), func(filePath string, dirEntry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				// fail
				return err
			}

			if path.Ext(dirEntry.Name()) == ".ra" {
				subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(dirEntry.Name(), -1)
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
				regex, err := runAssemble(filePath)
				if err != nil {
					return err
				}
				err = processRegexForCompare(id, uint8(chainOffset), regex, ctx)
				if err != nil && errors.Is(err, &ComparisonError{}) {
					failed = true
					return nil
				}
				if err != nil {
					return err
				}
				return nil
			}
			return nil
		})
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to compare expressions")
		}
		if failed && rootValues.output == gitHub {
			fmt.Println("::error::All rules need to be up to date.",
				"Please run `crs-toolchain regex update --all`")
			return &ComparisonError{}
		}
	} else {
		regex, err := runAssemble(path.Join(ctx.RootContext().AssemblyDir(), ruleValues.fileName))
		if err != nil {
			return err
		}
		return processRegexForCompare(ruleValues.id, ruleValues.chainOffset, regex, ctx)
	}
	return nil
}
func processRegexForCompare(ruleId string, chainOffset uint8, regex string, ctxt *processors.Context) error {
	logger.Info().Msgf("Processing %s, chain offset %d", ruleId, chainOffset)

	rulePrefix := ruleId[:3]
	matches, err := filepath.Glob(fmt.Sprintf("%s/*-%s-*", ctxt.RootContext().RulesDir(), rulePrefix))
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to find rule file for rule id %s", ruleId)
		return err
	}
	if matches == nil || len(matches) > 1 {
		logger.Error().Msgf("Failed to find rule file for rule id %s", ruleId)
		return err
	}

	filePath := matches[0]
	logger.Debug().Msgf("Processing regex-assembly file %s", filePath)

	currentRegex := readCurrentRegex(filePath, ruleId, chainOffset)
	return compareRegex(ruleId, regex, currentRegex)
}

func readCurrentRegex(filePath string, ruleId string, chainOffset uint8) string {
	contents, err := os.ReadFile(filePath)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to read rule file %s", filePath)
	}

	lines := bytes.Split(contents, []byte("\n"))

	idRegex := regexp.MustCompile(fmt.Sprintf("id:%s", ruleId))
	index := 0
	var line []byte
	foundRule := false
	chainCount := uint8(0)
	for index, line = range lines {
		if !foundRule && idRegex.Match(line) {
			foundRule = true
			if chainOffset == 0 {
				index--
				break
			}
			continue
		}
		if foundRule && regex.SecRuleRegex.Match(line) {
			chainCount++
		}
		if foundRule && chainCount == chainOffset {
			break
		}
	}
	if !foundRule || chainOffset != chainCount {
		logger.Fatal().Msgf("Failed to find rule %s, chain offset, %d in %s", ruleId, chainOffset, filePath)
	}
	regexLine := lines[index]
	found := regex.RuleRxRegex.FindAllStringSubmatch(string(regexLine), -1)
	if len(found) == 0 {
		logger.Fatal().Msgf("Failed to find rule %s in %s", ruleId, filePath)
	}
	return found[0][2]
}

func compareRegex(ruleId string, generatedRegex string, currentRegex string) error {
	if currentRegex == generatedRegex {
		fmt.Println("Regex of", ruleId, "has not changed")
		return nil
	} else if rootValues.output == gitHub {
		return &ComparisonError{}
	}

	fmt.Println("Regex of", ruleId, "has changed!")

	generatedRegexLines := splitByGroupsUpToDepth(generatedRegex, maxGroupSplittingDepth)
	currentRegexLines := splitByGroupsUpToDepth(currentRegex, maxGroupSplittingDepth)
	numLinesGenerated := len(generatedRegexLines)
	numLinesCurrent := len(currentRegexLines)
	skippedChars := 0
	for i := range max(numLinesCurrent, numLinesGenerated) {
		currentLine := ""
		generatedLine := ""
		if i < numLinesCurrent {
			currentLine = currentRegexLines[i]
		}
		if i < numLinesGenerated {
			generatedLine = generatedRegexLines[i]
		}
		if currentLine == generatedLine {
			skippedChars += len(currentLine)
			continue
		} else {
			if skippedChars > 0 {
				fmt.Printf("Skipped %d identical characters\n\n", skippedChars)
			}
			skippedChars = 0
		}

		os.Stdout.WriteString("current:    ")
		if i < numLinesCurrent {
			os.Stdout.WriteString(currentLine)
		} else {
			os.Stdout.WriteString("---")
		}

		os.Stdout.WriteString("\n")

		os.Stdout.WriteString("generated:  ")
		if i < numLinesGenerated {
			os.Stdout.WriteString(generatedLine)
		} else {
			os.Stdout.WriteString("---")
		}
		os.Stdout.WriteString("\n\n")
	}

	return &ComparisonError{}
}

func splitByGroupsUpToDepth(input string, maxDepth int) []string {
	lines := []string{input}
	for range maxDepth {
		lineBuffer := []string{}
		for _, line := range lines {
			newLines := splitByGroups(line)
			lineBuffer = append(lineBuffer, newLines...)
		}
		lines = lineBuffer
	}

	return lines
}

func splitByGroups(input string) []string {
	parenthesisCounter := 0
	lines := []string{}
	sb := strings.Builder{}
	for position, currentRune := range input {
		if currentRune == '(' && !utils.IsEscaped(input, position) {
			parenthesisCounter++
			if parenthesisCounter == 1 && sb.Len() > 0 {
				lines = append(lines, sb.String())
				sb.Reset()
			}
			sb.WriteRune(currentRune)

		} else if currentRune == ')' && !utils.IsEscaped(input, position) {
			parenthesisCounter--
			sb.WriteRune(currentRune)
			if parenthesisCounter <= 0 {
				lines = append(lines, sb.String())
				sb.Reset()
			}
		} else {
			sb.WriteRune(currentRune)
		}
	}
	if sb.Len() > 0 {
		lines = append(lines, sb.String())
	}

	if len(lines) == 1 && lines[0][0] == '(' && lines[0][len(lines[0])-1] == ')' {
		lines = splitByGroups(lines[0][1 : len(lines[0])-1])
		lines[0] = "(" + lines[0]
		lines[len(lines)-1] = lines[len(lines)-1] + ")"
	}
	return lines
}
