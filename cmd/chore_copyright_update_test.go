// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"
)

type choreCopyrightUpdateTestSuite struct {
	suite.Suite
	tempDir  string
	dataDir  string
	rulesDir string
}

func (s *choreCopyrightUpdateTestSuite) SetupTest() {
	rebuildChoreCommand()
	rebuildChoreCopyrightUpdateCommand()

	tempDir, err := os.MkdirTemp("", "copyright-update-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.NoError(err)

	s.rulesDir = path.Join(s.tempDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.NoError(err)

	s.writeRulesFile("TEST-900.conf", `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.0-rc1
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# This file REQUEST-901-INITIALIZATION.conf initializes the Core Rules`)
	s.FileExists(path.Join(s.rulesDir, "TEST-900.conf"))
}

func (s *choreCopyrightUpdateTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunCopyrightUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(choreCopyrightUpdateTestSuite))
}

func (s *choreCopyrightUpdateTestSuite) TestCopyrightUpdate_Version512() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "copyright-update", "-v", "5.1.2"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("copyright-update", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.1.2")
}

func (s *choreCopyrightUpdateTestSuite) TestCopyrightUpdate_Year2100() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "copyright-update", "-y", "2100"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("copyright-update", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.NoError(err)
	s.Contains(string(contents), "2021-2100")
}

func (s *choreCopyrightUpdateTestSuite) writeRulesFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.rulesDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}
