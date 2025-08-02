// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package selfUpdate

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/internal/updater"
)

var logger = log.With().Str("component", "cmd.util.self_update").Logger()

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "self-update",
		Short: "Performs self-update",
		Long: "Checks GitHub releases for the latest version of this command. If a new version is available, " +
			"it will get it and replace this binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			effectiveVersion := "dev"
			currentCmd := cmd
			for currentCmd.HasParent() {
				currentCmd = currentCmd.Parent()
				if cmd.Version != "" {
					effectiveVersion = cmd.Version
					break
				}
			}
			newVersion, err := updater.Updater(effectiveVersion, "")
			if err != nil {
				return err
			}
			if newVersion != "" {
				logger.Info().Msgf("Updated to version %s", newVersion)
			} else {
				logger.Info().Msg("No updates available")
			}
			return nil
		},
	}
}
