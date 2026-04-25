// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"

	release "github.com/coreruleset/crs-toolchain/v2/chore/release"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

var sourceRef string
var repositoryPath string
var version *semver.Version

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use: "release",
		// FIXME
		Short: "tbd",
		Args:  cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
		ValidArgs: []string{
			"version",
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			repositoryPath = args[0]

			if _, err := os.Stat(repositoryPath); err != nil {
				return err
			}

			var err error
			version, err = semver.NewVersion(args[1])
			if err != nil {
				return err
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(cmdContext.WorkingDirectory, cmdContext.ConfigurationFileName)
			release.Release(rootContext, repositoryPath, version, sourceRef)
		},
	}
	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&sourceRef, "source-ref", "s", "main", "Source reference for the release branch")
}
