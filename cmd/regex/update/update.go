// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package update

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

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

// parsedRuleValues holds the parsed values for a single rule
type parsedRuleValues struct {
	id          string
	fileName    string
	chainOffset uint8
}

var logger = log.With().Str("component", "cmd.regex.update").Logger()

func New(cmdContext *regexInternal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [RULE_ID | FILENAME...]",
		Short: "Update regular expressions in rule files",
		Long: `Update regular expressions in rule files.
This command will generate regular expressions from the data
files and update the associated rule.

RULE_ID is the ID of the rule, e.g., 932100.
FILENAME is the name of a regex-assembly file (e.g., 932100.ra, 932100-chain1.ra). The file extension is optional.
Multiple RULE_IDs and filenames can be specified in any order, separated by spaces.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
		Args: func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either RULE_ID(s)/filename(s) or --all flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either RULE_ID(s)/filename(s) or --all flag, found both")
			}
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			for _, arg := range args {
				baseName := extractBasename(arg)
				_, err := parseRuleIdToStruct(baseName)
				if err != nil {
					cmd.PrintErrf("failed to parse the rule ID/filename from the input '%s'\n", arg)
					return err
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctxt := processors.NewContext(cmdContext.RootContext())
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				return fmt.Errorf("failed to read value for 'all' flag: %w", err)
			}

			if processAll {
				return performUpdateAll(ctxt, cmdContext)
			}
			var parsedRules []parsedRuleValues
			for _, arg := range args {
				parsedRule, err := parseAndValidateArgument(arg, ctxt)
				if err != nil {
					return fmt.Errorf("failed to parse argument '%s': %w", arg, err)
				}
				parsedRules = append(parsedRules, parsedRule)
			}
			return performUpdateMultiple(parsedRules, ctxt, cmdContext)
		},
	}

	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("all", "a", false, `Instead of supplying RULE_ID(s)/filename(s), you can tell the script to
update all rules from their regex-assembly files`)
}

// extractBasename extracts the basename from a path or filename argument
func extractBasename(arg string) string {
	return filepath.Base(filepath.Clean(arg))
}

// parseAndValidateArgument parses an argument and validates that the corresponding file exists
func parseAndValidateArgument(arg string, ctxt *processors.Context) (parsedRuleValues, error) {
	baseName := extractBasename(arg)
	parsedRule, err := parseRuleIdToStruct(baseName)
	if err != nil {
		return parsedRuleValues{}, fmt.Errorf("failed to parse argument '%s': %s", arg, err.Error())
	}
	filePath := path.Join(ctxt.RootContext().AssemblyDir(), parsedRule.fileName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return parsedRuleValues{}, fmt.Errorf("file '%s' not found in assembly directory", parsedRule.fileName)
	}
	return parsedRule, nil
}

// parseChainOffset parses and validates a chain offset string
func parseChainOffset(chainOffsetString string) (uint8, error) {
	chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
	if err != nil && len(chainOffsetString) > 0 {
		return 0, errors.New("failed to match chain offset. Value must not be larger than 255")
	}
	return uint8(chainOffset), nil
}

// parseRuleIdToStruct parses a rule ID and returns a parsedRuleValues struct
func parseRuleIdToStruct(idAndChainOffset string) (parsedRuleValues, error) {
	subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(idAndChainOffset, -1)
	if subs == nil {
		return parsedRuleValues{}, errors.New("failed to match rule ID")
	}

	fileName := subs[0][0]
	id := subs[0][1]

	chainOffset, err := parseChainOffset(subs[0][2])
	if err != nil {
		return parsedRuleValues{}, err
	}

	if filepath.Ext(fileName) == "" {
		fileName += ".ra"
	}

	return parsedRuleValues{
		id:          id,
		fileName:    fileName,
		chainOffset: chainOffset,
	}, nil
}

func performUpdateAll(ctx *processors.Context, cmdContext *regexInternal.CommandContext) error {
	err := filepath.WalkDir(ctx.RootContext().AssemblyDir(), func(filePath string, dirEntry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			// fail
			return err
		}

		if dirEntry.IsDir() && filePath != ctx.RootContext().AssemblyDir() {
			return filepath.SkipDir
		}

		if path.Ext(dirEntry.Name()) == ".ra" {
			subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(dirEntry.Name(), -1)
			if subs == nil {
				// continue
				return nil
			}

			id := subs[0][1]
			chainOffset, err := parseChainOffset(subs[0][2])
			if err != nil {
				return err
			}

			return processRule(id, chainOffset, filePath, ctx, cmdContext)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func performUpdateMultiple(parsedRules []parsedRuleValues, ctx *processors.Context, cmdContext *regexInternal.CommandContext) error {
	for _, rule := range parsedRules {
		filePath := path.Join(ctx.RootContext().AssemblyDir(), rule.fileName)
		if err := processRule(rule.id, rule.chainOffset, filePath, ctx, cmdContext); err != nil {
			return err
		}
	}
	return nil
}

func processRule(ruleId string, chainOffset uint8, dataFilePath string, ctxt *processors.Context, cmdContext *regexInternal.CommandContext) error {
	logger.Info().Msgf("Processing %s, chain offset %d", ruleId, chainOffset)
	regex := regexInternal.RunAssemble(dataFilePath, ctxt.RootContext(), cmdContext)

	rulePrefix := ruleId[:3]
	matches, err := filepath.Glob(fmt.Sprintf("%s/*-%s-*", ctxt.RootContext().RulesDir(), rulePrefix))
	if err != nil {
		return fmt.Errorf("failed to find rule file for rule id %s: %w", ruleId, err)
	}
	if matches == nil || len(matches) > 1 {
		return fmt.Errorf("failed to find rule file for rule id %s", ruleId)
	}

	ruleFilePath := matches[0]
	logger.Debug().Msgf("Processing rule file %s for rule %s", ruleFilePath, ruleId)

	return updateRegex(ruleFilePath, ruleId, chainOffset, regex)
}

func updateRegex(filePath string, ruleId string, chainOffset uint8, newRegex string) error {
	contents, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read rule file %s: %w", filePath, err)
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
		return fmt.Errorf("failed to find rule %s, chain offset, %d in %s", ruleId, chainOffset, filePath)
	}

	regexLine := lines[index]
	found := regex.RuleRxRegex.FindAllStringSubmatch(string(regexLine), -1)
	if len(found) == 0 {
		return fmt.Errorf("failed to find rule %s in %s", ruleId, filePath)
	}
	updatedLine := found[0][1] + newRegex + found[0][3]
	lines[index] = []byte(updatedLine)

	err = os.WriteFile(filePath, bytes.Join(lines, []byte("\n")), fs.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to write rule file %s: %w", filePath, err)
	}
	return nil
}
