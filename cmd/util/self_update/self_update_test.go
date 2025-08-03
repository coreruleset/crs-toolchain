// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package selfUpdate

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/internal/updater"
)

type selfUpdateTestSuite struct {
	suite.Suite
	executablePath string
}

func (s *selfUpdateTestSuite) SetupTest() {
	var err error

	s.executablePath = path.Join(s.T().TempDir(), "crs-toolchain")
	err = os.WriteFile(s.executablePath, []byte("Fake Binary"), fs.ModePerm)
	s.Require().NoError(err)
}

func TestRunSelfUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(selfUpdateTestSuite))
}

func (s *selfUpdateTestSuite) TestSelfUpdateDev() {
	_, err := updater.Updater("v0.0.0-dev", s.executablePath)
	s.Require().NoError(err)
}

func (s *selfUpdateTestSuite) TestSelfUpdateBigVersion() {
	newVersion, err := updater.Updater("v10000.1.1", s.executablePath)
	s.Require().NoError(err)
	s.Equal("v10000.1.1", newVersion)
}

func (s *selfUpdateTestSuite) TestSelfUpdateWithExecutablePath() {
	newVersion, err := updater.Updater("v1.3.7", s.executablePath)
	s.Require().NoError(err)
	s.NotEmpty(newVersion)

	s.FileExists(s.executablePath, "The executable should exist")
	contents, err := os.ReadFile(s.executablePath)
	s.Require().NoError(err)
	s.NotContains(string(contents), "Fake Binary", "The executable should be replaced")

	var out, stderr bytes.Buffer

	cmd := exec.Command(s.executablePath, "version")
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		versionString := fmt.Sprintf("crs-toolchain %s", newVersion)
		s.Contains(out.String(), versionString)
	} else {
		s.Equal("exit status 1", err.Error())
		oldBinaryWithUnsupportedVersionFlagError := "Error: unknown command \"version\" for \"crs-toolchain\"\nRun 'crs-toolchain --help' for usage.\n"
		s.Equal(oldBinaryWithUnsupportedVersionFlagError, stderr.String())
	}
}
