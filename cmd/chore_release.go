// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/Masterminds/semver/v3"
	"github.com/coreruleset/crs-toolchain/v2/chore"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/spf13/cobra"
)

var choreReleaseCmd = createChoreReleaseCommand()

func init() {
	buildChoreReleaseCommand()
}

func createChoreReleaseCommand() *cobra.Command {
	return &cobra.Command{
		Use: "release",
		// FIXME
		Short: "tbd",
		Args:  cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
		ValidArgs: []string{
			"version",
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			repositoryPath := args[0]
			version := args[1]

			if _, err := os.Stat(repositoryPath); err != nil {
				return err
			}

			_, err := semver.NewVersion(version)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			version, err := semver.NewVersion(args[1])
			if err != nil {
				//FIXME
				panic(err)
			}
			chore.Release(rootContext, args[0], version)
		},
	}
}

func buildChoreReleaseCommand() {
	choreCmd.AddCommand(choreReleaseCmd)
}

func rebuildChoreReleaseCommand() {
	if choreReleaseCmd != nil {
		choreReleaseCmd.Parent().RemoveCommand(choreReleaseCmd)
	}

	choreReleaseCmd = createChoreReleaseCommand()
	buildChoreReleaseCommand()
}
