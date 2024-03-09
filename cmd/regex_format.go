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
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/context"
	"github.com/coreruleset/crs-toolchain/regex"
	"github.com/coreruleset/crs-toolchain/regex/parser"
	"github.com/coreruleset/crs-toolchain/regex/processors"
)

const (
	regexAssemblyStandardHeader = "##! Please refer to the documentation at\n##! https://coreruleset.org/docs/development/regex_assembly/.\n"
	showCharsAround             = 20
)

// formatCmd represents the generate command
var formatCmd = createFormatCommand()
var blockStartRegex = regex.ProcessorBlockStartRegex
var blockEndRegex = regex.ProcessorEndRegex
var includeRegex = regex.IncludeRegex
var includeExceptRegex = regex.IncludeExceptRegex
var definitionRegex = regex.DefinitionRegex
var prefixRegex = regex.PrefixRegex
var suffixRegex = regex.SuffixRegex
var flagsRegex = regex.FlagsRegex

func init() {
	buildFormatCommand()
}

func createFormatCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "format [RULE_ID | INCLUDE_NAME]",
		Short: "Format one or more regular expression regex-assembly files",
		Long: `Format one or more reguler expression regex-assembly files.

RULE_ID is the ID of the rule, e.g., 932100, or the regex-assembly file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.

INCLUDE_NAME is the name of the file in the "include" directory, without the extension.
These files are also regex-assembly files but don't follow the same naming
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
		RunE: func(cmd *cobra.Command, args []string) error {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			ctxt := processors.NewContext(rootContext)
			formatAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Error().Err(err).Msg("failed to read all flag")
				return err
			}
			checkOnly, err := cmd.Flags().GetBool("check")
			if err != nil {
				logger.Error().Err(err).Msg("failed to read check flag")
				return err
			}

			if formatAll {
				err = processAll(ctxt, checkOnly)
			} else {
				filename := args[0]
				if path.Ext(filename) == "" {
					filename += ".ra"
				}
				filePath := path.Join(ctxt.RootContext().IncludesDir(), filename)
				if err = parseRuleId(filename); err == nil {
					filePath = path.Join(ctxt.RootContext().AssemblyDir(), ruleValues.fileName)
				}
				err = processFile(filePath, ctxt, checkOnly)
			}

			if err != nil {
				// Errors are not command related
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
			}
			return err
		},
	}
}

func buildFormatCommand() {
	regexCmd.AddCommand(formatCmd)
	formatCmd.PersistentFlags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
format all assembly files (both regular and include files)`)
	formatCmd.Flags().BoolP("check", "c", false, `Do not write changes, simply report on files that would be formatted`)
}

func rebuildFormatCommand() {
	if formatCmd != nil {
		formatCmd.Parent().RemoveCommand(formatCmd)
	}

	formatCmd = createFormatCommand()
	buildFormatCommand()
}

func processAll(ctxt *processors.Context, checkOnly bool) error {
	failed := false
	err := filepath.WalkDir(ctxt.RootContext().AssemblyDir(), func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			// abort
			logger.Error().Err(err).Msg("failed to walk directories")
			return err
		}
		if d.IsDir() {
			// continue
			return nil
		}

		if path.Ext(d.Name()) == ".ra" {
			err := processFile(filePath, ctxt, checkOnly)
			if err != nil {
				failed = true
			}
			return nil
		}
		return nil
	})
	if err != nil {
		logger.Error().Err(err).Msg("failed to walk directories")
		return err
	}
	if failed {
		if rootValues.output == gitHub {
			fmt.Println("::error::All assembly files need to be properly formatted.",
				"Please run `crs-toolchain regex format --all`")
		}
		return &UnformattedFileError{}
	}
	return nil
}

func processFile(filePath string, ctxt *processors.Context, checkOnly bool) error {
	var processFileError error
	message := ""
	filename := path.Base(filePath)
	logger.Info().Msgf("Processing %s", filename)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to open file %s", filePath)
		return err
	}

	raParser := parser.NewParser(ctxt, file)
	parsedBytes, _ := raParser.Parse(true)
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
		line = formatLowercase(line, raParser)
		lines = append(lines, string(line))
	}

	if !checkStandardHeader(lines) {
		logger.Info().Msgf("file %s does not have standard header", filePath)
		// prepend the standard header
		lines = append([]string{regexAssemblyStandardHeader}, lines...)
	}
	lines = formatEndOfFile(lines)

	newContents := []byte(strings.Join(lines, "\n"))
	if checkOnly {
		currentContents, err := os.ReadFile(filePath)
		if err != nil {
			logger.Error().Err(err).Msgf("failed to read file %s", filePath)
			return err
		}
		equalContent := bytes.Equal(currentContents, newContents)
		if !equalContent {
			message = formatMessage(fmt.Sprintf("File %s not properly formatted", filePath))
			fmt.Println(message)
			processFileError = &UnformattedFileError{filePath: filePath}
		}
	} else {
		err = os.WriteFile(filePath, newContents, fs.ModePerm)
		if err != nil {
			logger.Error().Err(err).Msgf("failed to write file %s", filePath)
			processFileError = err
		}
	}

	return processFileError
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
		trimmedLine = []byte(fmt.Sprintf("##!> define %s %s", matches[2], matches[3]))
	} else if matches := includeRegex.FindSubmatch(line); matches != nil {
		trimmedLineString := fmt.Sprintf("##!> include %s", matches[1])
		if len(matches[2]) > 0 {
			trimmedLineString += fmt.Sprintf(" -- %s", matches[2])
		}
		trimmedLine = []byte(trimmedLineString)
	} else if matches := includeExceptRegex.FindSubmatch(line); matches != nil {
		trimmedLineString := fmt.Sprintf("##!> include-except %s %s", matches[1], matches[2])
		if len(matches[3]) > 0 {
			trimmedLineString += fmt.Sprintf(" -- %s", matches[3])
		}
		trimmedLine = []byte(trimmedLineString)
	}

	adjustment := bytes.Repeat([]byte(" "), blockIndent*2)
	trimmedLine = append(adjustment, trimmedLine...)

	return trimmedLine, nextIndent, nil
}

func formatLowercase(line []byte, raParser *parser.Parser) []byte {
	if !raParser.Flags['i'] {
		return line
	}

	// if this line is not a definition, then ignore if it is a comment
	definition := definitionRegex.Match(line)
	if !definition && regex.CommentRegex.Match(line) {
		return line
	}

	contentToCheck := line
	if definition {
		contentToCheck = definitionRegex.FindSubmatch(line)[3]
	}

	runes := bytes.Runes(contentToCheck)
	foundIndexes := findUppercaseNonEscaped(runes)
	if len(foundIndexes) > 0 {
		logger.Warn().Msgf("File contains uppercase letters, but ignore-case flag is set. Please check your source files.")
		// show the column where the uppercase letter was found
		// for a better visual match, we add equal symbols a and a caret in a line below
		index := foundIndexes[0]
		fill := ""
		if definition {
			index += definitionRegex.FindSubmatchIndex([]byte(line))[3]
		}
		if index > 0 {
			fill = strings.Repeat("=", index)
		}
		logger.Warn().Msgf("\n%s\n%s^ [HERE]\n", line, fill)
		logger.Warn().Msg("Be aware that because of file inclusions and definitions, the actual line number or file might be different.")
	}

	for _, index := range foundIndexes {
		runes[index] = unicode.ToLower(runes[index])
	}

	transformed := []byte(string(runes))
	if definition {
		startIndex := definitionRegex.FindSubmatchIndex(line)[3]
		transformed = append(line[:startIndex], transformed...)
	}
	return transformed
}

func formatMessage(message string) string {
	if rootValues.output == gitHub {
		message = fmt.Sprintf("::warning ::%s\n", message)
	}
	return message
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

func checkStandardHeader(lines []string) bool {
	if len(lines) >= 3 &&
		fmt.Sprintf("%s\n%s\n%s", lines[0], lines[1], lines[2]) == regexAssemblyStandardHeader {
		return true
	}
	return false
}

// findUppercaseNonEscaped finds all uppercase ASCII characters in the input that are not escaped.
// Returns an array with the indexes of all matches.
func findUppercaseNonEscaped(input []rune) []int {
	foundIndexes := []int{}
	for i, r := range input {
		if r >= 'A' && r <= 'Z' {
			// go back and check if the character is escaped
			count := 0
			for j := i - 1; j >= 0; j-- {
				if input[j] == '\\' {
					// we found a backslash, so we need to check if it is escaped
					count++
					// if the character is not escaped, return the index
				} else {
					break
				}
			}
			if count%2 == 0 {
				foundIndexes = append(foundIndexes, i)
			}
		}
	}
	return foundIndexes
}
