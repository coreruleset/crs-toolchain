// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/rs/zerolog"
)

// The types in this file satisfy the interface of pflag.Value.
// Using the pflag.Value interface makes it possible to validate
// flag values at parse time, as opposed to using `persistentPreRunE`,
// which would also work, except that persistent run functions will run
// in the child command first, which means that a global flag, like
// `--log-level`, would only be processed `after` other flags, and
// logging as part of flag value validation would then be useless.

type outputType string
type logLevel string

// TODO: Use proper types that encapsulate printing logic
const (
	text   outputType = "text"
	gitHub outputType = "github"
)

func (o *outputType) String() string {
	return string(*o)
}

func (o *outputType) Set(value string) error {
	switch value {
	case string(text), string(gitHub):
		rootValues.output = outputType(value)
		return nil
	default:
		return fmt.Errorf("invalid option for output: '%s'", value)
	}
}

func (o *outputType) Type() string {
	return "output type"
}

func (l *logLevel) String() string {
	level, _ := zerolog.ParseLevel(string(*l))
	return level.String()
}

func (l *logLevel) Set(value string) error {
	parsedLogLevel, err := zerolog.ParseLevel(value)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to parse log level '%s'", value)
		return err
	}
	// Set the global log level as a side effect. This is what we
	// really want to do.
	zerolog.SetGlobalLevel(parsedLogLevel)
	*l = logLevel(value)
	logger.Debug().Msgf("Set log level to '%s'", parsedLogLevel)

	return nil
}

func (l *logLevel) Type() string {
	return "log level"
}
