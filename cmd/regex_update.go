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
	"strings"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/operators"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

// parsedRuleValues holds the parsed values for a single rule
type parsedRuleValues struct {
	id          string
	fileName    string
	chainOffset uint8
	filePath    string // The actual path to the file (either relative or in assembly dir)
}

// updateCmd represents the update command
var updateCmd = createUpdateCommand()

func init() {
	buildUpdateCommand()
}

func createUpdateCommand() *cobra.Command {

	return &cobra.Command{
		Use:   "update [RULE_ID | FILENAME...]",
		Short: "Update regular expressions in rule files",
		Long: `Update regular expressions in rule files.
This command will generate regular expressions from the data
files and update the associated rule.

RULE_ID is the ID of the rule, e.g., 932100.
FILENAME is the name of a regex-assembly file (e.g., 932100.ra, 932100-chain1.ra).
Relative paths are also supported (e.g., regex-assembly/932100.ra) for pre-commit scenarios.
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
			// Validate all provided arguments
			for _, arg := range args {
				// Handle relative paths by extracting the basename for validation
				baseName := extractBasename(arg)
				
				err := parseRuleIdValidation(baseName)
				if err != nil {
					cmd.PrintErrf("failed to parse the rule ID/filename from the input '%s'\n", arg)
					return err
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			ctxt := processors.NewContext(rootContext)
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				return fmt.Errorf("failed to read value for 'all' flag: %w", err)
			}
			
			if processAll {
				return performUpdateAll(ctxt)
			} else {
				// Parse all arguments
				var parsedRules []parsedRuleValues
				for _, arg := range args {
					parsedRule, err := parseAndValidateArgument(arg, ctxt)
					if err != nil {
						return fmt.Errorf("failed to parse argument '%s': %w", arg, err)
					}
					parsedRules = append(parsedRules, parsedRule)
				}
				return performUpdateMultiple(parsedRules, ctxt)
			}
		},
	}
}

func buildUpdateCommand() {
	regexCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolP("all", "a", false, `Instead of supplying RULE_ID(s)/filename(s), you can tell the script to
update all rules from their regex-assembly files`)
}

func rebuildUpdateCommand() {
	if updateCmd != nil {
		updateCmd.Parent().RemoveCommand(updateCmd)
	}

	updateCmd = createUpdateCommand()
	buildUpdateCommand()
}

// isPath returns true if the argument contains path separators
func isPath(arg string) bool {
	// More reliable than checking for specific separators - works cross-platform
	return filepath.Dir(arg) != "."
}

// extractBasename extracts the basename from a path argument
func extractBasename(arg string) string {
	if isPath(arg) {
		basename := filepath.Base(arg)
		logger.Debug().Msgf("Extracted basename '%s' from path '%s'", basename, arg)
		return basename
	}
	return arg
}

// parseAndValidateArgument parses an argument and validates that the corresponding file exists
func parseAndValidateArgument(arg string, ctxt *processors.Context) (parsedRuleValues, error) {
	// Handle relative paths by extracting the basename
	// This supports pre-commit scenarios where files are passed as relative paths
	baseName := extractBasename(arg)
	
	// Parse the basename using the existing rule ID logic (handles both RULE_IDs and filenames)
	parsedRule, err := parseRuleIdToStruct(baseName)
	if err != nil {
		return parsedRuleValues{}, fmt.Errorf("failed to parse argument '%s': %s", arg, err.Error())
	}
	
	// For relative paths, check if the file exists at the given path first
	// This supports pre-commit scenarios where the file path is provided directly
	if isPath(arg) {
		// Check if the file exists at the relative path
		if _, err := os.Stat(arg); err == nil {
			// File exists at the relative path, we can proceed
			logger.Debug().Msgf("Found file at relative path: %s", arg)
			parsedRule.filePath = arg
			return parsedRule, nil
		} else {
			// Some other error occurred
			return parsedRuleValues{}, fmt.Errorf("error checking file '%s': %w", arg, err)
		}
		// File doesn't exist at relative path, fall through to check in assembly directory
	}
	
	// Check if the file exists in the assembly directory (existing logic)
	filePath := path.Join(ctxt.RootContext().AssemblyDir(), parsedRule.fileName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return parsedRuleValues{}, fmt.Errorf("file '%s' not found in assembly directory or at relative path", parsedRule.fileName)
	}
	
	parsedRule.filePath = filePath
	return parsedRule, nil
}

// parseRuleIdValidation validates a rule ID without storing state (for PreRunE)
func parseRuleIdValidation(idAndChainOffset string) error {
	subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(idAndChainOffset, -1)
	if subs == nil {
		return errors.New("failed to match rule ID")
	}

	chainOffsetString := subs[0][2]
	_, err := strconv.ParseUint(chainOffsetString, 10, 8)
	if err != nil && len(chainOffsetString) > 0 {
		return errors.New("failed to match chain offset. Value must not be larger than 255")
	}

	return nil
}

// parseRuleIdToStruct parses a rule ID and returns a parsedRuleValues struct
func parseRuleIdToStruct(idAndChainOffset string) (parsedRuleValues, error) {
	subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(idAndChainOffset, -1)
	if subs == nil {
		return parsedRuleValues{}, errors.New("failed to match rule ID")
	}

	fileName := subs[0][0]
	id := subs[0][1]
	chainOffsetString := subs[0][2]

	chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
	if err != nil && len(chainOffsetString) > 0 {
		return parsedRuleValues{}, errors.New("failed to match chain offset. Value must not be larger than 255")
	}

	if !strings.HasSuffix(fileName, ".ra") {
		fileName += ".ra"
	}

	return parsedRuleValues{
		id:          id,
		fileName:    fileName,
		chainOffset: uint8(chainOffset),
		filePath:    "", // Will be set by the calling function
	}, nil
}

func performUpdateAll(ctx *processors.Context) error {
	err := filepath.WalkDir(ctx.RootContext().AssemblyDir(), func(filePath string, dirEntry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			// fail
			return err
		}

		if !dirEntry.IsDir() && path.Ext(dirEntry.Name()) == ".ra" {
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

			err = processRule(id, uint8(chainOffset), filePath, ctx)
			if err != nil {
				return err
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func performUpdateMultiple(parsedRules []parsedRuleValues, ctx *processors.Context) error {
	for _, rule := range parsedRules {
		err := processRule(rule.id, rule.chainOffset, rule.filePath, ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func runAssemble(filePath string) (string, error) {
	rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
	ctxt := processors.NewContext(rootContext)
	assembler := operators.NewAssembler(ctxt)
	var input []byte
	var err error
	if ruleValues.useStdin {
		logger.Trace().Msg("Reading from stdin")
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read from stdin: %w", err)
		}
	} else {
		logger.Trace().Msgf("Reading from %s", filePath)
		input, err = os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read regex-assembly file %s: %w", filePath, err)
		}
	}
	assembly, err := assembler.Run(string(input))
	if err != nil {
		return "", err
	}
	return assembly, nil
}

func processRule(ruleId string, chainOffset uint8, dataFilePath string, ctxt *processors.Context) error {
	logger.Info().Msgf("Processing %s, chain offset %d", ruleId, chainOffset)
	regex, err := runAssemble(dataFilePath)
	if err != nil {
		return err
	}

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
