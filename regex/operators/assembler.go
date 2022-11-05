// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/itchyny/rassemble-go"

	"github.com/theseion/crs-toolchain/v2/regex/parser"
	"github.com/theseion/crs-toolchain/v2/regex/processors"
)

var preprocessorStart = regexp.MustCompile(`^##!>\s*([a-z]+)(?:\s+([a-z]+))?`)
var preprocessorEnd = regexp.MustCompile(`^##!<`)

// Create the processor stack
var processorStack ProcessorStack
var processor processors.IProcessor

// NewAssembler creates a new Operator based on context.
func NewAssembler(ctx *processors.Context) *Operator {
	return &Operator{
		name:    "assemble",
		details: make(map[string]string),
		lines:   []string{},
		ctx:     ctx,
		stats:   NewStats(),
	}
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
	processor = processors.NewAssemble(a.ctx)
	processorStack.push(processor)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		logger.Trace().Msgf("parsing line: %q", line)

		if procline := preprocessorStart.FindStringSubmatch(line); len(procline) > 0 {
			if err := a.startPreprocessor(procline[1], procline[2:]); err != nil {
				return "", err
			}
		} else if preprocessorEnd.MatchString(line) {
			lines, err := a.endPreprocessor()
			if err != nil {
				return "", err
			}
			processor.Consume(lines)
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

	logger.Trace().Msg("Final alternation pass")
	result, err := a.runFinalPass()
	if err != nil {
		logger.Fatal().Err(err).Msg("Final pass failed")
	}

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
		result = a.useHexEscapes(result)
		logger.Trace().Msgf("After simplification assembly: %s\n", result)
		result = a.escapeDoublequotes(result)
		logger.Trace().Msgf("After escaping double quotes: %s\n", result)
		result = a.useHexBackslashes(result)
		logger.Trace().Msgf("After use hex backslashes: %s\n", result)
		result = a.includeVerticalTabInSpaceClass(result)
		logger.Trace().Msgf("After including vertical tabs: %s\n", result)
		result = a.dontUseFlagsForMetaCharacters(result)
		logger.Trace().Msgf("After removing meta character flags: %s\n", result)
	}

	if len(flagsPrefix) > 0 && len(result) > 0 {
		result = flagsPrefix + result
	}

	return result
}

func (a *Operator) runFinalPass() (string, error) {
	processor := processors.NewAssemble(a.ctx)
	for _, line := range a.lines {
		processor.ProcessLine(line)
	}
	result, err := processor.Complete()
	if err != nil {
		return "", err
	}
	return strings.Join(result, ""), nil
}

// Once the entire expression has been assembled, run one last
// pass to possibly simplify groups and concatenations.
func (a *Operator) runSimplificationAssembly(input string) string {
	logger.Trace().Msgf("Simplifying regex %s\n", input)
	result, err := rassemble.Join([]string{input})
	logger.Trace().Msgf("=> Simplified to %s\n", result)
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
// We simply replace the generated class with `[\s\v]` to fix this.
// Note that we could use `\s` for PCRE, but this will not work for re2
// compatible engines.
func (a *Operator) includeVerticalTabInSpaceClass(input string) string {
	logger.Trace().Msg("Fixing up regex to include \\v in white space class matches")
	result := strings.ReplaceAll(input, `[\t-\n\f-\r ]`, `[\s\v]`)
	result = strings.ReplaceAll(result, `[^\t-\n\f-\r ]`, `[^\s\v]`)
	// There's a range attached, can't just replace
	result = strings.ReplaceAll(result, `\t-\n\f-\r -`, `\s\v -`)
	return strings.ReplaceAll(result, `\t-\n\f-\r `, `\s\v`)
}

// rassemble-go doesn't provide an option to specify literals.
// Go itself would, via the `Literal` flag to `syntax.Parse`.
// As it is, escapes that are printable runes will be returned as such,
// which means we will have weird looking characters in our regex
// instead of hex escapes.
// To replace the characters with their hex escape sequence, we can simply
// take the decimal value of each byte (this might be a single byte of a
// multi-byte sequnce), check whether it is a printable character and
// then either append it to the output string or create the equivalent
// escape code.
//
// Note: presumes that hexadecimal escapes in the input create UTF-8
// sequences.
//
// Note: not all hex escapes in the input will be escaped in the
// output, but all printable non-printable characters, including
// `\v\n\r` and space (`\x32`).
func (a *Operator) useHexEscapes(input string) string {
	var sb strings.Builder
	for _, char := range input {
		// dec_value = ord(char)
		if char < 32 || char > 126 {
			sb.WriteString(`\x`)
			sb.WriteString(fmt.Sprintf("%x", char))
		} else {
			sb.WriteRune(char)
		}
	}
	return sb.String()
}

// The Go regexp/syntax library will convert a dot (`.`) into `(?-s:.)`,
// `^` to `(?m:^)`, `$` to (?m:$)`.
// We want to retain the original dot.
func (a *Operator) dontUseFlagsForMetaCharacters(input string) string {
	result := strings.ReplaceAll(input, "(?-s:.)", ".")
	result = strings.ReplaceAll(result, "(?m:^)", "^")
	return strings.ReplaceAll(result, "(?m:$)", "$")
}

func (a *Operator) startPreprocessor(processorName string, args []string) error {
	logger.Trace().Msgf("Found processor %s start\n", processorName)
	switch processorName {
	case "assemble":
		assemble := processors.NewAssemble(a.ctx)
		processorStack.push(assemble)
		processor = assemble
	case "cmdline":
		cmdType, err := processors.CmdLineTypeFromString(args[0])
		if err != nil {
			logger.Error().Err(err).Msgf("Wrong cmdline type used: %s\n", args[0])
			return err
		}
		cmdline := processors.NewCmdLine(a.ctx, cmdType)
		processorStack.push(cmdline)
		processor = cmdline
	default:
		logger.Error().Msgf("Unknown processor name found: %s\n", processorName)
		return errors.New("unknown processor found")
	}
	return nil
}

func (a *Operator) endPreprocessor() ([]string, error) {
	logger.Trace().Msg("Found processor end")
	lines, err := processor.Complete()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to complete processor")
		return nil, err
	}
	logger.Trace().Msgf("** Got lines from Processor: %v\n", lines)
	// remove actual processor. read from top next processor.
	_, err = processorStack.pop()
	if err != nil {
		logger.Error().Err(err).Msg("Mismatched end marker, processor stack is empty")
		return nil, err
	}
	processor, err = processorStack.top()
	if err != nil {
		logger.Error().Err(err).Msg("Ooops, nothing on top, processor stack is empty")
		return nil, err
	}
	return lines, nil
}
