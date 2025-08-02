// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package updateCopyright

import (
	"errors"
	"strconv"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/chore"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

var ErrUpdateCopyrightWithoutVersion = errors.New("version is needed to update the copyright. You can use 'git describe --tags' if using git")
var copyrightVariables struct {
	Version string
	Year    string
}

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-copyright",
		Short: "Updates the copyright in setup, example setup, and rule files",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if copyrightVariables.Version == "" {
				return ErrUpdateCopyrightWithoutVersion
			}
			if err := validateSemver(copyrightVariables.Version); err != nil {
				return err
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			chore.UpdateCopyright(cmdContext.RootContext(), copyrightVariables.Version, copyrightVariables.Year)
		},
	}

	buildFlags(cmd)
	return cmd
}

func validateSemver(version string) error {
	_, err := semver.NewVersion(version)
	if err != nil {
		return err
	}
	return nil
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&copyrightVariables.Year, "year", "y", strconv.Itoa(time.Now().Year()), "Four digit year")
	cmd.Flags().StringVarP(&copyrightVariables.Version, "version", "v", "", "Add this text as the version to the file.")
}
