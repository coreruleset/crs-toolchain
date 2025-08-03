// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package updateCopyright

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type choreUpdateCopyrightTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	rulesDir   string
	cmdContext *internal.CommandContext
	cmd        *cobra.Command
}

func (s *choreUpdateCopyrightTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err := os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.rulesDir = path.Join(s.rootDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	s.cmdContext = internal.NewCommandContext(s.rootDir)
	s.cmd = New(s.cmdContext)

	s.writeFile(path.Join(s.rulesDir, "TEST-900.conf"), `# ------------------------------------------------------------------------
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

	s.writeFile(path.Join(s.rootDir, "crs-setup.conf.example"), `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.9.0-dev
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# This file is the crs-setup.conf.example shipped with CRS`)
	s.FileExists(path.Join(s.rootDir, "crs-setup.conf.example"))
}

func TestRunUpdateCopyrightTestSuite(t *testing.T) {
	suite.Run(t, new(choreUpdateCopyrightTestSuite))
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_Version512() {
	s.cmd.SetArgs([]string{"update-copyright", "-v", "5.1.2"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.1.2")

	// check that crs-setup.conf.example was also modified
	contents, err = os.ReadFile(path.Join(s.rootDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.1.2")
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_Year2100() {
	s.cmd.SetArgs([]string{"update-copyright", "-y", "2100", "-v", "7.1.22"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.Require().NoError(err)
	s.Contains(string(contents), "2021-2100")

	// check that crs-setup.conf.example was also modified
	contents, err = os.ReadFile(path.Join(s.rootDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	s.Contains(string(contents), "2021-2100")
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_ErrIfNoVersion() {
	s.cmd.SetArgs([]string{"update-copyright", "-y", "2222"})
	cmd, err := s.cmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	s.Error(err, ErrUpdateCopyrightWithoutVersion)
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_DevRelease() {
	s.cmd.SetArgs([]string{"update-copyright", "-v", "5.4.3-dev"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev")
	s.NotContains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev-dev")

	// check that crs-setup.conf.example was also modified
	contents, err = os.ReadFile(path.Join(s.rootDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev")
	s.NotContains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev-dev")
}

func (s *choreUpdateCopyrightTestSuite) writeFile(filename string, contents string) {
	err := os.WriteFile(filename, []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}
