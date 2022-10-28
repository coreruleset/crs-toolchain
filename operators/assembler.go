// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/itchyny/rassemble-go"
	"github.com/theseion/crs-toolchain/v2/parser"
	"github.com/theseion/crs-toolchain/v2/processors"
	"regexp"
	"sort"
	"strings"
)

const (
	preprocessorStartRegex = `\s*##!>\s*([a-z]+)(?:\s+([a-z]+))?`
	preprocessorEndRegex   = `\s*##!<`
	doubleQuotesRegex      = `([^\\])"`
)

var regexes = struct {
	preprocessorStart regexp.Regexp
	preprocessorEnd   regexp.Regexp
	doubleQuotesRegex regexp.Regexp
}{
	preprocessorStart: *regexp.MustCompile(preprocessorStartRegex),
	preprocessorEnd:   *regexp.MustCompile(preprocessorEndRegex),
	doubleQuotesRegex: *regexp.MustCompile(doubleQuotesRegex),
}

// Create the processor stack
var processorStack ProcessorStack

// NewAssembler creates a new Operator based on context.
func NewAssembler(ctx *processors.Context) *Operator {
	a := &Operator{
		name:    "assemble",
		details: make(map[string]string),
		lines:   []string{},
		ctx:     ctx,
		stats:   NewStats(),
	}
	return a
}

func (a *Operator) Run(input string) (string, error) {
	processorStack = NewProcessorStack()
	logger.Trace().Msg("Starting assembler")
	assembleParser := parser.NewParser(a.ctx, strings.NewReader(input))
	lines, _ := assembleParser.Parse()
	logger.Trace().Msgf("Parsed lines: %v", lines)
	assembled, err := a.Assemble(assembleParser, lines)
	if p, _ := processorStack.top(); p != nil {
		return assembled, errors.New("stack has unprocessed items")
	}
	return assembled, err
}

func (a *Operator) Assemble(assembleParser *parser.Parser, input *bytes.Buffer) (string, error) {
	fileScanner := bufio.NewScanner(bytes.NewReader(input.Bytes()))
	fileScanner.Split(bufio.ScanLines)
	var processor processors.IProcessor = processors.NewAssemble(a.ctx)
	processorStack.push(processor)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		logger.Trace().Msgf("parsing line: %q", line)

		if procline := regexes.preprocessorStart.FindStringSubmatch(line); len(procline) > 0 {
			logger.Trace().Msgf("Found processor %s start\n", procline[1])
			switch procline[1] {
			case "assemble":
				assemble := processors.NewAssemble(a.ctx)
				processorStack.push(assemble)
				processor = assemble
			case "cmdline":
				cmdType, err := processors.CmdLineTypeFromString(procline[2])
				if err != nil {
					logger.Error().Err(err).Msgf("Wrong cmdline type used: %s\n", procline[2])
					return "", err
				}
				cmdline := processors.NewCmdLine(a.ctx, cmdType)
				processorStack.push(cmdline)
				processor = cmdline
			default:
				logger.Error().Msgf("Unknown processor name found: %s\n", procline[1])
				return "", errors.New("unknown processor found")
			}
		} else if regexes.preprocessorEnd.MatchString(line) {
			logger.Trace().Msg("Found processor end")
			lines, err := processor.Complete()
			if err != nil {
				logger.Error().Err(err).Msg("Failed to complete processor")
				return "", err
			}
			logger.Trace().Msgf("** Got lines from Processor: %v\n", lines)
			// remove actual processor. read from top next processor.
			_, err = processorStack.pop()
			if err != nil {
				logger.Error().Err(err).Msg("Mismatched end marker, processor stack is empty")
				return "", err
			}
			processor, err = processorStack.top()
			if err != nil {
				logger.Error().Err(err).Msg("Ooops, nothing on top, processor stack is empty")
				return "", err
			}
			a.lines = append(a.lines, lines...)
		} else {
			logger.Trace().Msg("Processor is processing line")
			processor.ProcessLine(line)
		}
	}

	processor, err := processorStack.top()
	if err != nil {
		logger.Error().Err(err).Msg("Mismatched end marker, processor stack is empty")
		return "", err
	}
	lines, err := processor.Complete()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to complete processor")
		return "", err
	}
	logger.Trace().Msgf("** Got lines from Processor: %v\n", lines)
	a.lines = append(a.lines, lines...)
	_, err = processorStack.pop()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to remove assembler processor.")
		return "", err
	}
	return a.complete(assembleParser), nil
}

func (a *Operator) complete(assembleParser *parser.Parser) string {
	logger.Trace().Msgf("** completing using: %v\n", a.lines)
	flagsPrefix := ""
	if len(assembleParser.Flags) > 0 {
		flags := make([]string, 0, len(assembleParser.Flags))
		for flag := range assembleParser.Flags {
			flags = append(flags, string(flag))
		}
		sort.Strings(flags)
		flagsPrefix = "(?" + strings.Join(flags, "") + ")"
	}

	result := strings.Join(a.lines, "")
	if len(assembleParser.Prefixes) > 0 && len(assembleParser.Suffixes) > 0 && len(result) > 0 {
		result = "(?:" + result + ")"
	}
	prefixes := strings.Join(assembleParser.Prefixes, "")
	suffixes := strings.Join(assembleParser.Suffixes, "")
	result = prefixes + result + suffixes

	if len(result) > 0 {
		logger.Trace().Msgf("Applying last cleanups to %s\n", result)
		result = a.runSimplificationAssembly(result)
		logger.Trace().Msgf("After simplification assembly: %s\n", result)
		result = a.escapeDoublequotes(result)
		logger.Trace().Msgf("After escaping double quotes: %s\n", result)
		result = a.useHexBackslashes(result)
		logger.Trace().Msgf("After use hex backslashes: %s\n", result)
		result = a.includeVerticalTabInBackslashS(result)
		logger.Trace().Msgf("After including vertical tabs: %s\n", result)
	}

	if len(flagsPrefix) > 0 {
		result = flagsPrefix + result
	}

	return result
}

// Once the entire expression has been assembled, run one last
// pass to possibly simplify groups and concatenations.
func (a *Operator) runSimplificationAssembly(input string) string {
	logger.Trace().Msg("Simplifying regex")
	result, err := rassemble.Join([]string{input})
	if err != nil {
		logger.Fatal().Err(err).Str("regex", input).Msg("Failed to simplify regex")
	}
	return result
}

// escapeDoublequotes takes a double quote and adds the `\` char before it.
// We need all double quotes to be escaped because we use them
// as delimiters in rules.
func (a *Operator) escapeDoublequotes(input string) string {
	logger.Trace().Msg("Escaping double quotes")
	binput := []byte(input)
	result := bytes.Buffer{}
	for k, v := range binput {
		if k == 0 && v == '"' {
			result.WriteString(`\"`)
		} else if k > 0 && v == '"' && binput[k-1] != '\\' {
			result.WriteString(`\"`)
		} else {
			result.WriteByte(v)
		}
	}
	return result.String()
}

// useHexBackslashes replaces all literal backslashes with `\x5c`,
// the hexadecimal representation of a backslash. This is for compatibility and
// readbility reasons, as Apache httpd handles sequences of backslashes
// differently than nginx.
func (a *Operator) useHexBackslashes(input string) string {
	logger.Trace().Msg("Replacing literal backslashes with \\x5c")
	return strings.ReplaceAll(input, `\\`, `\x5c`)
}

// In Perl, the vertical tab (`\v`, `\x0b`) is *not* part of `\s`, but it is
// in newer versions of PCRE (both 3 and 2). Go's `regexp/syntax` package
// uses Perl as the reference and, hence, generates `[\t-\n\f-\r ]` as the
// character class for `\s`, i.e., `\v` is missing.
// We simply replace the generated class with `\s` again to fix this.
func (a *Operator) includeVerticalTabInBackslashS(input string) string {
	logger.Trace().Msg("Fixing up regex to include \\v in white space class matches")
	result := strings.ReplaceAll(input, `[\t-\n\f-\r ]`, `\s`)
	result = strings.ReplaceAll(result, `[^\t-\n\f-\r ]`, `[^\s]`)
	// There's a range attached, can't just replace
	result = strings.ReplaceAll(result, `\t-\n\f-\r -`, `\s -`)
	return strings.ReplaceAll(result, `\t-\n\f-\r `, `\s`)
}
