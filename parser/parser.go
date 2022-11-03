// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

// Package parser implements the parsing logic to obtain the sequence of inputs ready for processing.
// The two main thing it will do is to parse a data file and recursively solve all `includes` first, then
// substitute all definitions where neccesary.
package parser

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/imdario/mergo"
	"github.com/rs/zerolog/log"

	"github.com/theseion/crs-toolchain/v2/processors"
)

var logger = log.With().Str("component", "parser").Logger()

type parsedType int

const (
	includePatternName    string     = "include"
	includePattern        string     = `^\s*##!>\s*include\s*(.*)$`
	definitionPatternName string     = "definition"
	definitionPattern     string     = `^\s*##!>\s*define\s+([a-zA-Z0-9-_]+)\s+(.*)$`
	commentPatternName    string     = "comment"
	commentPattern        string     = `\s*##![^^$+><=]`
	flagsPatternName      string     = "flags"
	flagsPattern          string     = `^\s*##!\+\s*(.*)\s*$`
	prefixPatternName     string     = "prefix"
	prefixPattern         string     = `^\s*##!\^\s*(.*)$`
	suffixPatternName     string     = "suffix"
	suffixPattern         string     = `^\s*##!\$\s*(.*)$`
	regular               parsedType = iota
	empty
	include
	definition
	comment
	flags
	prefix
	suffix
)

// Parser is the base parser type. It will provide processors with all the inclusions and definitions resolved.
type Parser struct {
	ctx       *processors.Context
	src       io.Reader
	dest      *bytes.Buffer
	variables map[string]string
	Flags     map[rune]bool
	Prefixes  []string
	Suffixes  []string
	patterns  map[string]*regexp.Regexp
}

// ParsedLine will store the results of parsing the line. `parsedType` will discriminate how you read the results:
// if the type is `include`, then the result map will store the file name in the "include" key. The definition type
// will just use the map for the name:value.
type ParsedLine struct {
	parsedType parsedType
	result     map[string]string
	line       string
}

// NewParser creates a new parser from an io.Reader.
func NewParser(ctx *processors.Context, reader io.Reader) *Parser {
	p := &Parser{
		ctx:       ctx,
		src:       reader,
		dest:      &bytes.Buffer{},
		variables: make(map[string]string),
		Flags:     make(map[rune]bool),
		Prefixes:  []string{},
		Suffixes:  []string{},
		patterns: map[string]*regexp.Regexp{
			includePatternName:    regexp.MustCompile(includePattern),
			definitionPatternName: regexp.MustCompile(definitionPattern),
			commentPatternName:    regexp.MustCompile(commentPattern),
			flagsPatternName:      regexp.MustCompile(flagsPattern),
			prefixPatternName:     regexp.MustCompile(prefixPattern),
			suffixPatternName:     regexp.MustCompile(suffixPattern),
		},
	}
	return p
}

// Parse does the parsing and returns a buffer with all the bytes to process or an error if the reader
// could not be parsed.
func (p *Parser) Parse() (*bytes.Buffer, int) {
	fileScanner := bufio.NewScanner(p.src)
	fileScanner.Split(bufio.ScanLines)
	wrote := 0
	var text string

	for fileScanner.Scan() {
		line := fileScanner.Text()
		text = "" // empty text each iteration
		logger.Trace().Msgf("parsing line: %q", line)
		parsedLine := p.parseLine(line)
		switch parsedLine.parsedType {
		case regular:
			text = line + "\n"
		// remove comments and empty lines from the parsed line
		case empty, comment:
			continue
		case definition:
			// merge maps p.variables and parseLine.definition
			err := mergo.Merge(&p.variables, parsedLine.result)
			if err != nil {
				logger.Error().Err(err).Msg("error merging definitions")
			}
		case include:
			// go read the included file and paste text here
			content, _ := includeFile(p.ctx, parsedLine.result[includePatternName])
			text = content.String()
		case flags:
			for _, flag := range parsedLine.result[flagsPatternName] {
				if flagIsAllowed(flag) {
					p.Flags[flag] = true
				} else {
					logger.Panic().Msgf("flag '%s' is not supported", string(flag))
				}
			}
		case prefix:
			p.Prefixes = append(p.Prefixes, parsedLine.result[prefixPatternName])
		case suffix:
			p.Suffixes = append(p.Suffixes, parsedLine.result[suffixPatternName])
		}
		// err is always nil
		logger.Trace().Msgf("** ADDING text: %q", text)
		n, _ := p.dest.WriteString(text)
		wrote += n
	}

	// now that the file was parsed, we replace all definitions
	if len(p.variables) > 0 {
		p.dest = expandDefinitions(p.dest, p.variables)
	}
	return p.dest, wrote
}

// parseLine iterates over the pattern list and if found, creates the ParsedLine object with the results.
func (p *Parser) parseLine(line string) ParsedLine {
	pl := ParsedLine{
		parsedType: regular,
		result:     make(map[string]string),
		line:       line,
	}
	if len(strings.TrimSpace(line)) == 0 {
		pl.parsedType = empty
		return pl
	}

	for name, pattern := range p.patterns {
		found := pattern.FindStringSubmatch(line)
		// found[0] has the whole line that matched, found[N] has the subgroup
		if len(found) > 0 {
			logger.Trace().Msgf("found %s statement: %v", name, found[0])
			switch name {
			case commentPatternName:
				pl.parsedType = comment
				pl.result[name] = "comment"
			case includePatternName:
				pl.parsedType = include
				pl.result[name] = found[1]
			case definitionPatternName:
				pl.parsedType = definition
				pl.result[found[1]] = found[2]
			case flagsPatternName:
				pl.parsedType = flags
				pl.result[name] = found[1]
			case prefixPatternName:
				pl.parsedType = prefix
				pl.result[name] = found[1]
			case suffixPatternName:
				pl.parsedType = suffix
				pl.result[name] = found[1]
			}
			break
		}
	}
	return pl
}

// includeFile does just a new call to the Parser on the named file. It will use the context to find files that have relative filenames.
func includeFile(ctx *processors.Context, filename string) (*bytes.Buffer, int) {
	logger.Trace().Msgf("reading filename: %v", filename)
	// check if filename has an absolute path
	// if it is relative, use the context to get the parent directory where we should search for the file.
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(ctx.IncludeDir(), filename)
	}
	readFile, err := os.Open(filename)
	if err != nil {
		logger.Fatal().Msgf("cannot open file for inclusion: %v", err.Error())
	}
	newP := NewParser(ctx, bufio.NewReader(readFile))
	return newP.Parse()
}

func expandDefinitions(src *bytes.Buffer, variables map[string]string) *bytes.Buffer {
	logger.Trace().Msgf("expanding definitions in: %v", src.String())
	// Templates can contain templates themeselves
	for needle, replacement := range variables {
		needle := "{{" + needle + "}}"
		for sourceName, source := range variables {
			variables[sourceName] = strings.ReplaceAll(source, needle, replacement)
		}
	}
	// Now replace templates in the rest of the file
	for needle, replacement := range variables {
		needle := "{{" + needle + "}}"
		src = bytes.NewBuffer(bytes.ReplaceAll(src.Bytes(), []byte(needle), []byte(replacement)))
	}
	logger.Trace().Msgf("expanded all definitions in: %v", src.String())
	return src
}

func flagIsAllowed(flag rune) bool {
	allowed := false
	switch flag {
	case 'i', 's':
		allowed = true
	}
	return allowed
}
