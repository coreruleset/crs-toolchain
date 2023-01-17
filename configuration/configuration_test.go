// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type configurationTestSuite struct {
	suite.Suite
	tempDir     string
	assemblyDir string
}

func (s *configurationTestSuite) writeConfig(config *Configuration) {
	filePath := filepath.Join(s.assemblyDir, "toolchain.yaml")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	s.NoError(err)

	encoder := yaml.NewEncoder(file)
	err = encoder.Encode(config)
	s.NoError(err)
}

func (s *configurationTestSuite) SetupTest() {
	tempDir, err := os.MkdirTemp("", "configuration-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.assemblyDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.assemblyDir, fs.ModePerm)
	s.NoError(err)
}

func (s *configurationTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunconfigurationTestSuite(t *testing.T) {
	suite.Run(t, new(configurationTestSuite))
}

func (s *configurationTestSuite) TestReadingConfiguration() {
	s.writeConfig(newTestConfiguration())

	readConfiguration := New(s.assemblyDir)
	s.NotNil(readConfiguration)
	s.Equal(readConfiguration, newTestConfiguration())
}

func newTestConfiguration() *Configuration {
	return &Configuration{
		Patterns: Patterns{
			AntiEvasion: Pattern{
				Unix:    "_av-u_",
				Windows: "_av-w_",
			},
			AntiEvasionSuffix: Pattern{
				Unix:    "_av-u-suffix_",
				Windows: "_av-w-suffix_",
			},
			AntiEvasionNoSpaceSuffix: Pattern{
				Unix:    "_av-ns-u-suffix_",
				Windows: "_av-ns-w-suffix_",
			},
		},
	}
}
