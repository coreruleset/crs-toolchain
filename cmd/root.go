// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const defaultLogLevel = zerolog.InfoLevel

// rootCmd represents the base command when called without any subcommands
var rootCmd = createRootCommand()
var logger = log.With().Str("component", "cmd").Logger()
var rootValues = struct {
	output                outputType
	logLevel              logLevel
	workingDirectory      workingDirectory
	configurationFileName configurationFileName
}{}

func Execute(version, commit, date, builtBy string) {
	rootCmd.Version = version
	versionTemplate := fmt.Sprintf("{{with .Name}}"+
		"{{printf \"%%s \" .}}{{end}}"+
		"{{printf \"version %%s\\ncommit %s\\ndate %s\\nbuiltBy %s\\n\" .Version}}",
		commit, date, builtBy)
	rootCmd.SetVersionTemplate(versionTemplate)
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to resolve working directory")
	}
	rootValues = struct {
		output                outputType
		logLevel              logLevel
		workingDirectory      workingDirectory
		configurationFileName configurationFileName
	}{
		output:                text,
		logLevel:              logLevel(defaultLogLevel.String()),
		workingDirectory:      workingDirectory(cwd),
		configurationFileName: configurationFileName("toolchain.yaml"),
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
		`Set the application log level
Options: 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', 'disabled'`)
	rootCmd.PersistentFlags().VarP(&rootValues.output, "output", "o", "Output format. One of 'text', 'github'.")
	rootCmd.PersistentFlags().VarP(&rootValues.workingDirectory, "directory", "d",
		`Absolute or relative path to the CRS directory.
If not specified, the command is assumed to run inside the CRS directory`)
	rootCmd.PersistentFlags().VarP(&rootValues.configurationFileName, "configuration", "f",
		"Name of the configuration file")
}

func rebuildRootCommand() {
	rootCmd = createRootCommand()
	rootValues.output = "text"
	rootValues.logLevel = logLevel(defaultLogLevel.String())

	buildRootCommand()
}
