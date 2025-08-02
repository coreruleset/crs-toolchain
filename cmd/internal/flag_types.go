// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/rs/zerolog"
)

// The types in this file satisfy the interface of pflag.Value.
// Using the pflag.Value interface makes it possible to validate
// flag values at parse time, as opposed to using `persistentPreRunE`,
// which would also work, except that persistent run functions will run
// in the child command first, which means that a global flag, like
// `--log-level`, would only be processed `after` other flags, and
// logging as part of flag value validation would then be useless.

type OutputTypeFlag struct {
	Context *CommandContext
}
type LogLevelFlag struct {
	Context *CommandContext
	Logger  *zerolog.Logger
}
type WorkingDirectoryFlag struct {
	Context *CommandContext
	Logger  *zerolog.Logger
}
type ConfigurationFileNameFlag struct {
	Context *CommandContext
	Logger  *zerolog.Logger
}

const (
	Text   string = "text"
	GitHub string = "github"
)

func (o *OutputTypeFlag) String() string {
	return o.Context.Output
}

func (o *OutputTypeFlag) Set(value string) error {
	switch value {
	case Text, GitHub:
		o.Context.Output = value
		return nil
	default:
		return fmt.Errorf("invalid option for output: '%s'", value)
	}
}

func (o *OutputTypeFlag) Type() string {
	return "output type"
}

func (l *LogLevelFlag) String() string {
	return l.Context.LogLevel.String()
}

func (l *LogLevelFlag) Set(value string) error {
	parsedLogLevel, err := zerolog.ParseLevel(value)
	if err != nil {
		l.Logger.Error().Err(err).Msgf("Failed to parse log level '%s'", value)
		return err
	}
	// Set the global log level as a side effect. This is what we
	// really want to do.
	zerolog.SetGlobalLevel(parsedLogLevel)
	l.Context.LogLevel = parsedLogLevel
	l.Logger.Trace().Msgf("Set log level to '%s'", parsedLogLevel)

	return nil
}

func (l *LogLevelFlag) Type() string {
	return "log level"
}

func (w *WorkingDirectoryFlag) String() string {
	return w.Context.WorkingDirectory
}

func (w *WorkingDirectoryFlag) Set(value string) error {
	absPath, err := filepath.Abs(value)
	if err != nil {
		w.Logger.Error().Err(err).Msgf("Failed to construct absolute path from %s", value)
		return err
	}

	root, err := w.findRootDirectory(absPath)
	if err != nil {
		w.Logger.Error().Err(err).Msgf("Failed to find root directory from %s", absPath)
		return err
	}

	w.Logger.Debug().Msgf("Resolved root directory %s", root)
	w.Context.WorkingDirectory = root
	return nil
}

func (w *WorkingDirectoryFlag) Type() string {
	return "working directory"
}

func (c *ConfigurationFileNameFlag) String() string {
	return c.Context.ConfigurationFileName
}

func (c *ConfigurationFileNameFlag) Set(value string) error {
	c.Context.ConfigurationFileName = value
	return nil
}

func (c *ConfigurationFileNameFlag) Type() string {
	return "configuration filename"
}

func (w *WorkingDirectoryFlag) findRootDirectory(startPath string) (string, error) {
	w.Logger.Trace().Msgf("Searching for root directory starting at %s", startPath)
	dataPath := "regex-assembly"
	currentPath := startPath
	// root directory only will have a separator as the last rune
	for currentPath[len(currentPath)-1] != filepath.Separator {

		_, err := os.Stat(path.Join(currentPath, dataPath))
		if err != nil {
			currentPath = path.Dir(currentPath)
			w.Logger.Trace().Msgf("Root directory not found yet. Trying %s", currentPath)
			continue
		}

		return currentPath, nil
	}

	return "", errors.New("failed to find root directory")
}
