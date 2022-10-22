// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

// Package parser implements the parsing logic to obtain the sequence of inputs ready for processing.
// The two main thing it will do is to parse a data file and recursively solve all `includes` first, then
// substitute all templates where neccesary.
package parser

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"regexp"

	"github.com/rs/zerolog/log"
)

const (
	IncludePattern  string = `^\s*##!>\s*include\s*(.*)$`
	TemplatePattern string = `^\s*##!>\s*template\s+([a-zA-Z0-9-_]+)\s+(.*)$`
	RegularType     int    = 0
	IncludeType     int    = 1
	TemplateType    int    = 2
)

type Parser struct {
	src       io.Reader
	variables map[string]string
	dest      *bytes.Buffer
}

type ParsedLine struct {
	parsedType  int
	includeFile string
	template    map[string]string
	line        string
}

// NewParser creates a new parser from a io.Reader.
func NewParser(reader io.Reader) *Parser {
	p := &Parser{
		src:       reader,
		variables: make(map[string]string),
		dest:      &bytes.Buffer{},
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
		log.Debug().Str("component", "parser").Msgf("parsing line: %q", line)
		parsedLine := parseLine(line)
		switch parsedLine.parsedType {
		case RegularType:
			text = line + "\n"
		case TemplateType:
			// merge maps p.variables and parseLine.template
			text = "something"
		case IncludeType:
			// go read the included file and paste text here
			dest, err := includeFile(parsedLine.includeFile)
			if err != nil {
				log.Fatal().Str("component", "parser").Msgf("couldn't include file: %s", parsedLine.includeFile)
			}
			text = dest.String()
		}
		// err is always nil
		n, _ := p.dest.WriteString(text)
		wrote += n
	}

	// now that the file was parsed, we replace all templates
	if len(p.variables) > 0 {
		replaceTemplates(p.dest, p.variables)
	}
	return p.dest, wrote
}

func parseLine(line string) ParsedLine {
	var pl ParsedLine
	include := regexp.MustCompile(IncludePattern)
	found := include.FindStringSubmatch(line)
	// found[0] has the whole line that matched, found[1] has the subgroup
	if len(found) > 0 {
		log.Debug().Str("component", "parser").Msgf("found include statement: %s", found[1])
		pl = ParsedLine{
			parsedType:  IncludeType,
			includeFile: found[1],
		}
		return pl
	}
	template := regexp.MustCompile(TemplatePattern)
	found = template.FindStringSubmatch(line)
	if len(found) > 0 {
		log.Debug().Str("component", "parser").Msgf("found template: %s -> %s", found[1], found[2])
		pl = ParsedLine{
			parsedType: TemplateType,
			template: map[string]string{
				found[0]: found[1],
			},
		}
		return pl
	}
	pl = ParsedLine{
		parsedType: RegularType,
		line:       line,
	}
	return pl
}

// includeFile does just a new call to the Parser on the named file.
func includeFile(filename string) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	readFile, err := os.Open(filename)
	if err != nil {
		return &buf, err
	}
	newP := NewParser(bufio.NewReader(readFile))
	return newP.dest, err
}

func replaceTemplates(src *bytes.Buffer, variables map[string]string) {
	for needle, replacement := range variables {
		src = bytes.NewBuffer(bytes.ReplaceAll(src.Bytes(), []byte(needle), []byte(replacement)))
	}
}
