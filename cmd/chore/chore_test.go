// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package chore

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type choreTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	rulesDir   string
	cmdContext *internal.CommandContext
	cmd        *cobra.Command
}

func (s *choreTestSuite) SetupTest() {
	tempDir, err := os.MkdirTemp("", "chore-tests")
	s.Require().NoError(err)
	s.rootDir = tempDir

	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.rulesDir = path.Join(s.rootDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	s.cmdContext = internal.NewCommandContext(s.rootDir)
	s.cmd = New(s.cmdContext)
}

func TestRunChoreTestSuite(t *testing.T) {
	suite.Run(t, new(choreTestSuite))
}

func (s *choreTestSuite) TestChore_UpdateCopyright() {
	var filename = "TEST-900.conf"
	var ruleTemplateString = `# ------------------------------------------------------------------------
# OWASP CRS ver.{{.version}}
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-{{.year}} CRS project. All rights reserved.
#
# The OWASP CRS is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# This file REQUEST-901-INITIALIZATION.conf initializes the Core Rules`

	ruleTemplate, err := template.New("test-rule").Parse(ruleTemplateString)
	s.Require().NoError(err)
	oldVars := map[string]any{
		"version": "v4.0.0-rc1",
		"year":    2022,
	}
	version := "1.2.3"
	year := "2024"
	buffer := &bytes.Buffer{}
	err = ruleTemplate.Execute(buffer, oldVars)
	s.Require().NoError(err)
	s.writeRulesFile(filename, buffer.String())
	s.cmd.SetArgs([]string{"update-copyright", "-v", version, "-y", year})
	_, err = s.cmd.ExecuteC()
	s.Require().NoError(err, "failed to execute rootCmd")

	contents := s.readRulesFile(filename)
	newVars := map[string]any{
		"version": version,
		"year":    year,
	}
	buffer.Reset()
	err = ruleTemplate.Execute(buffer, newVars)
	s.Require().NoError(err)
	actual := strings.TrimSuffix(contents, "\n")
	s.Equal(buffer.String(), actual)
}

func (s *choreTestSuite) writeRulesFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.rulesDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *choreTestSuite) readRulesFile(filename string) string {
	contents, err := os.ReadFile(path.Join(s.rulesDir, filename))
	s.Require().NoError(err)
	return string(contents)
}
