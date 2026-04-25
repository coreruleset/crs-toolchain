// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/chore"
	"github.com/coreruleset/crs-toolchain/v2/cmd/completion"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/cmd/regex"
	"github.com/coreruleset/crs-toolchain/v2/cmd/util"
)

var logger = log.With().Str("component", "cmd").Logger()
var configurationFileNameFlag *internal.ConfigurationFileNameFlag
var logLevelFlag *internal.LogLevelFlag
var outputTypeFlag *internal.OutputTypeFlag
var workingDirectoryFlag *internal.WorkingDirectoryFlag

func Execute(version, commit, date, builtBy string) {
	rootCmd := New()
	// Setting `Version` generates a `--version` flag
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

func New() *cobra.Command {
	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to resolve working directory")
	}
	cmdContext := internal.NewCommandContext(cwd)
	rootCmd := &cobra.Command{
		Use:   "crs-toolchain",
		Short: "The Core Ruleset toolchain",
	}

	buildFlags(rootCmd, cmdContext)
	rootCmd.AddCommand(
		chore.New(cmdContext),
		completion.New(),
		regex.New(cmdContext),
		util.New(cmdContext),
	)
	return rootCmd
}

func buildFlags(rootCmd *cobra.Command, cmdContext *internal.CommandContext) {
	configurationFileNameFlag = &internal.ConfigurationFileNameFlag{Context: cmdContext, Logger: &logger}
	logLevelFlag = &internal.LogLevelFlag{Context: cmdContext, Logger: &logger}
	outputTypeFlag = &internal.OutputTypeFlag{Context: cmdContext}
	workingDirectoryFlag = &internal.WorkingDirectoryFlag{Context: cmdContext, Logger: &logger}

	rootCmd.PersistentFlags().VarP(logLevelFlag, "log-level", "l",
		`Set the application log level
Options: 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', 'disabled'`)
	rootCmd.PersistentFlags().VarP(outputTypeFlag, "output", "o", "Output format. One of 'text', 'github'.")
	rootCmd.PersistentFlags().VarP(workingDirectoryFlag, "directory", "d",
		`Absolute or relative path to the CRS directory.
If not specified, the command is assumed to run inside the CRS directory`)
	rootCmd.PersistentFlags().VarP(configurationFileNameFlag, "configuration", "f",
		"Name of the configuration file")
}
