// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const defaultLogLevel = zerolog.ErrorLevel

// rootCmd represents the base command when called without any subcommands
var rootCmd = createRootCommand()
var logger zerolog.Logger
var rootValues = struct {
	output           outputType
	logLevel         logLevel
	workingDirectory workingDirectory
}{}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	zerolog.SetGlobalLevel(defaultLogLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "03:04:05"})
	logger = log.With().Str("component", "cmd").Caller().Logger()

	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to resolve working directory")
	}
	rootValues = struct {
		output           outputType
		logLevel         logLevel
		workingDirectory workingDirectory
	}{
		output:           text,
		logLevel:         logLevel(zerolog.LevelErrorValue),
		workingDirectory: workingDirectory(cwd),
	}

	buildRootCommand()
}

func createRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "crs-toolchain",
		Short: "The Core Ruleset toolchain",
	}
}

func buildRootCommand() {
	rootCmd.PersistentFlags().VarP(&rootValues.logLevel, "log-level", "l",
		`Set the application log level. Default: 'error'.
Options: 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', 'disabled`)
	rootCmd.PersistentFlags().VarP(&rootValues.output, "output", "o", "Output format. One of 'text', 'github'. Default: 'text'")
	rootCmd.PersistentFlags().VarP(&rootValues.workingDirectory, "directory", "d",
		"Absolute or relative path to the CRS directory. If not specified, the command is assumed to run inside the CRS directory.")
}

func rebuildRootCommand() {
	rootCmd = createRootCommand()
	rootValues.output = "text"
	rootValues.logLevel = logLevel(defaultLogLevel.String())

	buildRootCommand()
}
