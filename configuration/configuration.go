// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultDictionaryCommitRef = "refs/heads/master"

type Configuration struct {
	Patterns Patterns
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

func New(directory string, filename string) *Configuration {
	configFilePath := filepath.Join(directory, filename)
	newConfiguration := &Configuration{}

	file, err := os.Open(configFilePath)
	if err != nil {
		return newConfiguration
	}

	decoder := yaml.NewDecoder(file)
	if err = decoder.Decode(newConfiguration); err != nil {
		// don't use the initialized struct, it might have been partially filled
		return &Configuration{}
	}

	// FIXME: Is there a better way to process the parsed strings? TextUnmarshaler is an option but then I'd have to add another type etd...
	newConfiguration.Patterns.AntiEvasion.Unix = strings.TrimSpace(newConfiguration.Patterns.AntiEvasion.Unix)
	newConfiguration.Patterns.AntiEvasion.Windows = strings.TrimSpace(newConfiguration.Patterns.AntiEvasion.Windows)
	newConfiguration.Patterns.AntiEvasionSuffix.Unix = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionSuffix.Unix)
	newConfiguration.Patterns.AntiEvasionSuffix.Windows = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionSuffix.Windows)
	newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Unix = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Unix)
	newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Windows = strings.TrimSpace(newConfiguration.Patterns.AntiEvasionNoSpaceSuffix.Windows)

	return newConfiguration
}
