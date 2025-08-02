// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserIncludeWithDefinitions struct {
	suite.Suite
	rootDir     string
	includeDir  string
	includeFile []*os.File
	ctx         *processors.Context
	reader      io.Reader
}

func TestRunParserIncludeWithDefinitionsTestSuite(t *testing.T) {
	suite.Run(t, new(parserIncludeWithDefinitions))
}

func (s *parserIncludeWithDefinitions) TestParser_IncludeWithDefinitions() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString(
		"This is comment 3.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"This is comment 2.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"This is comment 1.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"[a-zA-J]+8 to see if definitions work.\n" +
			"Second text for [0-9](pine|apple).\n")

	s.NotEmpty(parser.variables)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found definition variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found definition variables in map")
	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeWithDefinitions) TestParser_DanglingDefinitions() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	reader := strings.NewReader("##!> define hello world\n{{hello}}\n{{hallo}}\n")
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	parser := NewParser(processors.NewContext(rootContext), reader)

	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString("world\n{{hallo}}\n")
	s.Equal(expected.String(), actual.String())

	s.Contains(out.String(), "no match found for definition: {{hallo}}")
}

func (s *parserIncludeWithDefinitions) SetupSuite() {
	s.rootDir = s.T().TempDir()
	s.includeDir = path.Join(s.rootDir, "regex-assembly", "include")
	err := os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := context.New(filepath.Dir(s.rootDir), "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
	for i := 0; i < 4; i++ {
		file, err := os.Create(path.Join(s.rootDir, fmt.Sprintf("multi-definitions-%d.ra", i)))
		s.Require().NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf(
				"##!> include %s\n"+
					"##!> define this-is-a-text [a-zA-J]+8\n"+
					"##!> define this-is-another-text [0-9](pine|apple)\n"+
					"{{this-is-a-text}} to see if definitions work.\n"+
					"Second text for {{this-is-another-text}}.\n", file.Name()))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := fmt.Fprintf(s.includeFile[i-1],
				"##!> include %s\n"+
					"This is comment %d.\n"+
					"{{this-is-a-text}} to see if definitions work when included\n", file.Name(), i)
			s.Require().NoError(err, "writing temp include file failed")
		}
	}
}
