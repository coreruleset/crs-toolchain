// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/theseion/crs-toolchain/v2/regex/parser"
	"github.com/theseion/crs-toolchain/v2/regex/processors"
)

// formatCmd represents the generate command
var formatCmd = createFormatCommand()
var blockStartRegex = regexp.MustCompile(`^##!>\s*(assemble|cmdline)\s*(\S+)?`)
var blockEndRegex = regexp.MustCompile(`^##!<`)
var includeRegex = regexp.MustCompile(parser.IncludePattern)
var definitionRegex = regexp.MustCompile(parser.DefinitionPattern)
var prefixRegex = regexp.MustCompile(parser.PrefixPattern)
var suffixRegex = regexp.MustCompile(parser.SuffixPattern)
var flagsRegex = regexp.MustCompile(parser.FlagsPattern)

func init() {
	buildFormatCommand()
}

func createFormatCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "format [RULE_ID | INCLUDE_NAME]",
		Short: "Format one or more regular expression data files",
		Long: `Format one or more reguler expression data files.

RULE_ID is the ID of the rule, e.g., 932100, or the data file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.

INCLUDE_NAME is the name of the a file in the "include" directory.
These files are also data files but don't follow the same naming
scheme, as they don't correspond to any particular rule.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected RULE_ID, INCLUDE_NAME, or flag, found nothing")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected RULE_ID, INCLUDE_NAME, or flag, found multiple")
			} else if len(args) == 1 && args[0] == "-" {
				return errors.New("invalid argument '-'")
			}

			return nil
		}),
		Run: func(cmd *cobra.Command, args []string) {
			ctxt := processors.NewContext(rootValues.workingDirectory.String())
			formatAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to read all flag")
			}
			if formatAll {
				err = processAll(ctxt)
			} else {
				filename := args[0]
				if path.Ext(filename) == "" {
					filename += ".data"
				}
				filePath := path.Join(ctxt.RootContext().IncludeDir(), filename)
				if err = parseRuleId(filename); err == nil {
					filePath = path.Join(ctxt.RootContext().DataDir(), ruleValues.fileName)
				}
				err = processFile(filePath, ctxt)
			}

			if err != nil {
				logger.Fatal().Err(err).Msg("formatting failed")
			}
		},
	}
}

func buildFormatCommand() {
	regexCmd.AddCommand(formatCmd)
	formatCmd.PersistentFlags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
format all data files (both regular and include files)`)
}

func rebuildFormatCommand() {
	if formatCmd != nil {
		formatCmd.Parent().RemoveCommand(formatCmd)
	}

	formatCmd = createFormatCommand()
	buildFormatCommand()
}

func processAll(ctxt *processors.Context) error {
	err := filepath.WalkDir(ctxt.RootContext().DataDir(), func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			// abort
			logger.Error().Err(err).Msg("failed to walk directories")
			return err
		}
		if d.IsDir() {
			// continue
			return nil
		}

		if path.Ext(d.Name()) == ".data" {
			return processFile(filePath, ctxt)
		}
		return nil
	})
	if err != nil {
		logger.Error().Err(err).Msg("failed to walk directories")
		return err
	}
	return nil
}

func processFile(filePath string, ctxt *processors.Context) error {
	filename := path.Base(filePath)
	logger.Info().Msgf("Formatting %s", filename)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to open file %s", filePath)
		return err
	}
	parser := parser.NewParser(ctxt, file)
	parsedBytes, _ := parser.Parse(true)
	if err = file.Close(); err != nil {
		logger.Error().Err(err).Msgf("file already closed %s", filePath)
		return err
	}

	scanner := bufio.NewScanner(parsedBytes)
	scanner.Split(bufio.ScanLines)
	lines := []string{}

	indent := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		line, indent, err = processLine(line, indent)
		if err != nil {
			logger.Error().Err(err).Msgf("failed to format %s", filename)
		}
		lines = append(lines, string(line))
	}

	lines = formatEndOfFile(lines)

	err = os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), fs.ModePerm)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to write file %s", filePath)
		return err
	}

	return nil
}

func processLine(line []byte, indent int) ([]byte, int, error) {
	trimmedLine := bytes.TrimLeft(line, " \t")
	if len(trimmedLine) == 0 {
		return trimmedLine, indent, nil
	}

	blockIndent := indent
	nextIndent := indent
	if matches := blockStartRegex.FindSubmatch(line); matches != nil {
		newLine := fmt.Sprintf("##!> %s", matches[1])
		if len(matches[2]) > 0 {
			newLine += " " + string(matches[2])
		}
		trimmedLine = []byte(newLine)
		blockIndent = indent
		nextIndent = blockIndent + 1
	} else if blockEndRegex.Match(line) {
		if blockIndent == 0 {
			return nil, 0, errors.New("unbalanced processor block")
		}
		blockIndent = indent - 1
		nextIndent = blockIndent
	} else if matches := flagsRegex.FindSubmatch(line); matches != nil {
		trimmedLine = []byte(fmt.Sprintf("##!+ %s", matches[1]))
		blockIndent = 0
	} else if matches := prefixRegex.FindSubmatch(line); matches != nil {
		trimmedLine = []byte(fmt.Sprintf("##!^ %s", matches[1]))
		blockIndent = 0
	} else if matches := suffixRegex.FindSubmatch(line); matches != nil {
		trimmedLine = []byte(fmt.Sprintf("##!$ %s", matches[1]))
		blockIndent = 0
	} else if matches := definitionRegex.FindSubmatch(line); matches != nil {
		trimmedLine = []byte(fmt.Sprintf("##!> define %s %s", matches[1], matches[2]))
	} else if matches := includeRegex.FindSubmatch(line); matches != nil {
		trimmedLine = []byte(fmt.Sprintf("##!> include %s", matches[1]))
	}

	adjustment := bytes.Repeat([]byte(" "), blockIndent*2)
	trimmedLine = append(adjustment, trimmedLine...)

	return trimmedLine, nextIndent, nil
}

func formatEndOfFile(lines []string) []string {
	eof := len(lines) - 1
	if eof < 0 {
		// Lines will be joined with newlines, so
		// two empty lines will result in a single
		// newline character
		return append(lines, "", "")
	}

	for i := eof; i >= 0; i-- {
		line := lines[i]
		if line == "" {
			eof--
		} else {
			break
		}
	}
	// Append a single empty line, which will be joined
	// to the others by newline
	return append(lines[:eof+1], "")
}
