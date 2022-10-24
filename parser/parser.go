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

type ParsedType int

const (
	IncludePatternName  string     = "include"
	IncludePattern      string     = `^\s*##!>\s*include\s*(.*)$`
	TemplatePatternName string     = "template"
	TemplatePattern     string     = `^\s*##!>\s*template\s+([a-zA-Z0-9-_]+)\s+(.*)$`
	Regular             ParsedType = iota
	Include
	Template
)

// Parser is the base parser type. It will provide processors with all the inclusions and templates resolved.
type Parser struct {
	src       io.Reader
	dest      *bytes.Buffer
	variables map[string]string
	patterns  map[string]*regexp.Regexp
}

// ParsedLine will store the results of parsing the line. `parsedType` will discriminate how you read the results:
// if the type is `Include`, then the result map will store the file name in the "include" key. The template type
// will just use the map for the name:value.
type ParsedLine struct {
	parsedType ParsedType
	result     map[string]string
	line       string
}

// NewParser creates a new parser from an io.Reader.
func NewParser(reader io.Reader) *Parser {
	log.Debug().Str("component", "parser").Msgf("creating new parser")
	p := &Parser{
		src:       reader,
		dest:      &bytes.Buffer{},
		variables: make(map[string]string),
		patterns: map[string]*regexp.Regexp{
			IncludePatternName:  regexp.MustCompile(IncludePattern),
			TemplatePatternName: regexp.MustCompile(TemplatePattern),
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
		log.Debug().Str("component", "parser").Msgf("parsing line: %q", line)
		parsedLine := p.parseLine(line)
		switch parsedLine.parsedType {
		case Regular:
			text = line + "\n"
		case Template:
			// merge maps p.variables and parseLine.template
			text = "something"
		case Include:
			// go read the included file and paste text here
			content, _ := includeFile(parsedLine.result[IncludePatternName])
			text = content.String()
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

// parseLine iterates over the pattern list and if found, creates the ParsedLine object with the results.
func (p *Parser) parseLine(line string) ParsedLine {
	var pl ParsedLine
	var result map[string]string
	pType := Regular

	for name, pattern := range p.patterns {
		found := pattern.FindStringSubmatch(line)
		// found[0] has the whole line that matched, found[N] has the subgroup
		if len(found) > 0 {
			log.Debug().Str("component", "parser").Msgf("found %s statement: %v", name, found[1:])
			switch name {
			case IncludePatternName:
				pType = Include
				result = map[string]string{
					name: found[1],
				}
			case TemplatePatternName:
				pType = Template
				result = map[string]string{
					found[1]: found[2],
				}
			}
			break
		}
	}

	pl = ParsedLine{
		parsedType: pType,
		result:     result,
		line:       line,
	}
	return pl
}

// includeFile does just a new call to the Parser on the named file.
func includeFile(filename string) (*bytes.Buffer, int) {
	readFile, err := os.Open(filename)
	if err != nil {
		log.Fatal().Str("component", "parser").Msgf("cannot open file for inclusion: %v", err.Error())
	}
	newP := NewParser(bufio.NewReader(readFile))
	return newP.Parse()
}

func replaceTemplates(src *bytes.Buffer, variables map[string]string) {
	for needle, replacement := range variables {
		src = bytes.NewBuffer(bytes.ReplaceAll(src.Bytes(), []byte(needle), []byte(replacement)))
	}
}
