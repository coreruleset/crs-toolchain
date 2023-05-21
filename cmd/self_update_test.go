// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"
)

type selfUpdateTestSuite struct {
	suite.Suite
	tempDir        string
	executablePath string
}

func (s *selfUpdateTestSuite) SetupTest() {
	var err error
	rebuildSelfUpdateCommand()
	s.tempDir, err = os.MkdirTemp("", "self-update-tests")
	s.NoError(err)

	s.executablePath = path.Join(s.tempDir, "crs-toolchain")
	err = os.WriteFile(s.executablePath, []byte("Fake Binary"), fs.ModePerm)
	s.NoError(err)
}

func (s *selfUpdateTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunSelfUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(selfUpdateTestSuite))
}

func (s *selfUpdateTestSuite) TestSelfUpdateDev() {
	newVersion, err := selfUpdateMe("dev", s.executablePath)
	s.NoError(err)
	s.Empty(newVersion)
}

func (s *selfUpdateTestSuite) TestSelfUpdateBigVersion() {
	newVersion, err := selfUpdateMe("v10000.1.1", s.executablePath)
	s.NoError(err)
	s.Empty(newVersion)
}

func (s *selfUpdateTestSuite) TestSelfUpdateWithExecutablePath() {
	newVersion, err := selfUpdateMe("v1.3.7", s.executablePath)
	s.NoError(err)
	s.NotEmpty(newVersion)

	s.FileExists(s.executablePath, "The executable should exist")
	contents, err := os.ReadFile(s.executablePath)
	s.NoError(err)
	s.NotContains(string(contents), "Fake Binary", "The executable should be replaced")

	var out, stderr bytes.Buffer

	cmd := exec.Command(s.executablePath, "version")
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		versionString := fmt.Sprintf("crs-toolchain version %s", newVersion)
		s.Equal(versionString, out.String())
	} else {
		s.Equal("exit status 1", err.Error())
		oldBinaryWithUnsupportedVersionFlagError := "Error: unknown command \"version\" for \"crs-toolchain\"\nRun 'crs-toolchain --help' for usage.\n"
		s.Equal(oldBinaryWithUnsupportedVersionFlagError, stderr.String())
	}
}
