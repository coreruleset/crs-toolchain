// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/internal/updater"
)

// selfUpdateCmd represents the self-updater command
var selfUpdateCmd = createSelfUpdateCommand()

func init() {
	buildSelfUpdateCommand()
}

func createSelfUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "self-update",
		Short: "Performs self-update",
		Long: "Checks GitHub releases for the latest version of this command. If a new version is available, " +
			"it will get it and replace this binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Start running. If an error occurs, propagate but don't print anything
			// command related.
			//cmd.SilenceErrors = true
			//cmd.SilenceUsage = true
			return selfUpdateMe()
		},
	}
}

func buildSelfUpdateCommand() {
	rootCmd.AddCommand(selfUpdateCmd)
}

func rebuildSelfUpdateCommand() {
	if selfUpdateCmd != nil {
		selfUpdateCmd.Parent().RemoveCommand(selfUpdateCmd)
	}

	selfUpdateCmd = createSelfUpdateCommand()
	buildSelfUpdateCommand()
}

func selfUpdateMe() error {
	return updater.Updater(rootCmd.Version)
}
