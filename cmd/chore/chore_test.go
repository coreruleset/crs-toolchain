// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package chore

import (
	"io/fs"
	"os"
	"path"
	"testing"

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
	rebuildChoreCommand()
	rebuildChoreUpdateCopyrightCommand()
	rebuildChoreReleaseCommand()

	tempDir, err := os.MkdirTemp("", "chore-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "regex-assembly")
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

func (s *choreTestSuite) TestChore_RulesFile() {
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "update-copyright", "-v", "1.2.3", "-y", "2024"})
	_, err := rootCmd.ExecuteC()

	s.Require().NoError(err, "failed to execute rootCmd")
}

func (s *choreTestSuite) writeRulesFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.rulesDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}
