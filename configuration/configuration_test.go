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
	"go.yaml.in/yaml/v4"
)

type configurationTestSuite struct {
	suite.Suite
	tempDir     string
	assemblyDir string
}

func (s *configurationTestSuite) writeConfig(config *Configuration) {
	filePath := filepath.Join(s.assemblyDir, "toolchain.yaml")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	s.Require().NoError(err)

	encoder := yaml.NewEncoder(file)
	err = encoder.Encode(config)
	s.Require().NoError(err)
}

func (s *configurationTestSuite) SetupTest() {
	tempDir, err := os.MkdirTemp("", "configuration-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.assemblyDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.assemblyDir, fs.ModePerm)
	s.Require().NoError(err)
}

func (s *configurationTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestRunconfigurationTestSuite(t *testing.T) {
	suite.Run(t, new(configurationTestSuite))
}

func (s *configurationTestSuite) TestReadingConfiguration() {
	s.writeConfig(newTestConfiguration())

	readConfiguration := New(s.assemblyDir, "toolchain.yaml")
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
		PhpDictionaryGen: PhpDictionaryGen{
			PhpRepoURL:              DefaultPhpRepoURL,
			PhpMajorVersionCount:    DefaultPhpMajorVersionCount,
			FrequencyLimit:          DefaultFrequencyLimit,
			AgeLimitDays:            DefaultAgeLimitDays,
			Rule933150FileName:      DefaultRule933150FileName,
			Rule933151FileName:      DefaultRule933151FileName,
			Rule933152FileName:      DefaultRule933152FileName,
			Rule933153FileName:      DefaultRule933153FileName,
			Rule933161FileName:      DefaultRule933161FileName,
			MaxRateLimitWaitSeconds: DefaultMaxRateLimitWaitSecs,
		},
	}
}

func (s *configurationTestSuite) TestPhpDictionaryGenDefaults_AppliedWhenUnset() {
	s.writeConfig(&Configuration{})

	readConfiguration := New(s.assemblyDir, "toolchain.yaml")
	s.Equal(DefaultPhpRepoURL, readConfiguration.PhpDictionaryGen.PhpRepoURL)
	s.Equal(DefaultPhpMajorVersionCount, readConfiguration.PhpDictionaryGen.PhpMajorVersionCount)
	s.Equal(DefaultFrequencyLimit, readConfiguration.PhpDictionaryGen.FrequencyLimit)
	s.Equal(DefaultAgeLimitDays, readConfiguration.PhpDictionaryGen.AgeLimitDays)
	s.Equal(DefaultRule933150FileName, readConfiguration.PhpDictionaryGen.Rule933150FileName)
	s.Equal(DefaultMaxRateLimitWaitSecs, readConfiguration.PhpDictionaryGen.MaxRateLimitWaitSeconds)
}

func (s *configurationTestSuite) TestPhpDictionaryGenDefaults_OverriddenByConfig() {
	s.writeConfig(&Configuration{
		PhpDictionaryGen: PhpDictionaryGen{
			PhpRepoURL:     "https://example.invalid/php-src",
			FrequencyLimit: 42,
		},
	})

	readConfiguration := New(s.assemblyDir, "toolchain.yaml")
	s.Equal("https://example.invalid/php-src", readConfiguration.PhpDictionaryGen.PhpRepoURL)
	s.Equal(42, readConfiguration.PhpDictionaryGen.FrequencyLimit)
	// Unset fields still fall back to their defaults.
	s.Equal(DefaultAgeLimitDays, readConfiguration.PhpDictionaryGen.AgeLimitDays)
}
