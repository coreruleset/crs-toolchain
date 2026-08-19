// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"

	release "github.com/coreruleset/crs-toolchain/v2/chore/release"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

var sourceRef string
var version *semver.Version

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release <version>",
		Short: "Create new release of CRS",
		Long: `Create a new release of CRS.

The repository to operate on is the CRS directory determined by the global
--directory flag, or the current working directory if that flag is not set.`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			version, err = semver.NewVersion(args[0])
			if err != nil {
				return fmt.Errorf("parsing version %q: %w", args[0], err)
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(cmdContext.WorkingDirectory, cmdContext.ConfigurationFileName)
			release.Release(rootContext, version, sourceRef)
		},
	}
	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&sourceRef, "source-ref", "s", "main", "Source reference for the release branch")
}
