// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v4"
)

const DefaultDictionaryCommitRef = "refs/heads/master"

// Defaults for PhpDictionaryGen, used whenever toolchain.yaml doesn't set a value.
const (
	DefaultPhpRepoURL           = "https://github.com/php/php-src"
	DefaultPhpMajorVersionCount = 3
	DefaultFrequencyLimit       = 90000
	DefaultAgeLimitDays         = 30
	DefaultRule933150FileName   = "php-function-names-933150.data"
	DefaultRule933151FileName   = "php-function-names-933151.ra"
	DefaultRule933152FileName   = "php-function-names-933152.ra"
	DefaultRule933153FileName   = "php-function-names-933153.ra"
	DefaultRule933161FileName   = "933161.ra"
	DefaultMaxRateLimitWaitSecs = 120
)

type Configuration struct {
	Patterns         Patterns
	PhpDictionaryGen PhpDictionaryGen `yaml:"php_dictionary_gen"`
}

type Patterns struct {
	AntiEvasion              Pattern `yaml:"anti_evasion"`
	AntiEvasionSuffix        Pattern `yaml:"anti_evasion_suffix"`
	AntiEvasionNoSpaceSuffix Pattern `yaml:"anti_evasion_no_space_suffix"`
}

type Pattern struct {
	Unix    string
	Windows string
}

// PhpDictionaryGen holds configuration for the `generate php-function-names` command.
// Any field left empty/zero falls back to the corresponding Default* constant.
type PhpDictionaryGen struct {
	// PhpRepoURL is the PHP source repository to clone when --php-repo isn't given.
	PhpRepoURL string `yaml:"php_repo_url"`
	// PhpMajorVersionCount is the number of most recent PHP major versions
	// (beyond the default branch) to also extract function names from. For
	// each major version considered, only its oldest and newest release
	// branch are scanned (see selectReleaseBranches in util/php_dictionary_gen.go).
	PhpMajorVersionCount int `yaml:"php_major_version_count"`
	// FrequencyLimit is the default minimum GitHub occurrence count to qualify for rule 933150.
	FrequencyLimit int `yaml:"frequency_limit"`
	// AgeLimitDays is the default number of days before a frequency cache entry is stale.
	AgeLimitDays int `yaml:"age_limit_days"`
	// Rule933150FileName..Rule933161FileName are the output file names for each generated rule.
	Rule933150FileName string `yaml:"rule_933150_file_name"`
	Rule933151FileName string `yaml:"rule_933151_file_name"`
	Rule933152FileName string `yaml:"rule_933152_file_name"`
	Rule933153FileName string `yaml:"rule_933153_file_name"`
	Rule933161FileName string `yaml:"rule_933161_file_name"`
	// MaxRateLimitWaitSeconds caps how long a rate-limited GitHub API request is retried after.
	MaxRateLimitWaitSeconds int `yaml:"max_rate_limit_wait_seconds"`
}

func New(directory string, filename string) *Configuration {
	configFilePath := filepath.Join(directory, filename)
	newConfiguration := &Configuration{}

	if file, err := os.Open(configFilePath); err == nil {
		defer file.Close()
		decoder := yaml.NewDecoder(file)
		if err := decoder.Decode(newConfiguration); err != nil {
			// don't use the partially filled struct
			newConfiguration = &Configuration{}
		}
	}

	// FIXME: Is there a better way to process the parsed strings? TextUnmarshaler is an option but then I'd have to add another type etd...
	newConfiguration.Patterns.AntiEvasion.Unix = strings.TrimSpace(newConfiguration.Patterns.AntiEvasion.Unix)
	newConfiguration.Patterns.AntiEvasion.Windows = strings.TrimSpace(newConfiguration.Patterns.AntiEvasion.Windows)
	newConfiguration.Patterns.AntiEvasionSuffix.Unix = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionSuffix.Unix)
	newConfiguration.Patterns.AntiEvasionSuffix.Windows = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionSuffix.Windows)
	newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Unix = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Unix)
	newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Windows = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Windows)

	applyPhpDictionaryGenDefaults(&newConfiguration.PhpDictionaryGen)

	return newConfiguration
}

func applyPhpDictionaryGenDefaults(c *PhpDictionaryGen) {
	if c.PhpRepoURL == "" {
		c.PhpRepoURL = DefaultPhpRepoURL
	}
	if c.PhpMajorVersionCount == 0 {
		c.PhpMajorVersionCount = DefaultPhpMajorVersionCount
	}
	if c.FrequencyLimit == 0 {
		c.FrequencyLimit = DefaultFrequencyLimit
	}
	if c.AgeLimitDays == 0 {
		c.AgeLimitDays = DefaultAgeLimitDays
	}
	if c.Rule933150FileName == "" {
		c.Rule933150FileName = DefaultRule933150FileName
	}
	if c.Rule933151FileName == "" {
		c.Rule933151FileName = DefaultRule933151FileName
	}
	if c.Rule933152FileName == "" {
		c.Rule933152FileName = DefaultRule933152FileName
	}
	if c.Rule933153FileName == "" {
		c.Rule933153FileName = DefaultRule933153FileName
	}
	if c.Rule933161FileName == "" {
		c.Rule933161FileName = DefaultRule933161FileName
	}
	if c.MaxRateLimitWaitSeconds == 0 {
		c.MaxRateLimitWaitSeconds = DefaultMaxRateLimitWaitSecs
	}
}
