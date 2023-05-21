// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/internal/updater"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of crs-toolchain",
	Long:  `All software has versions. This is crs-toolchain's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("crs-toolchain", rootCmd.Version)
		latest, err := updater.LatestVersion()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to check for updates")
		} else if latest != "" {
			fmt.Println("Latest version is:", latest)
			fmt.Println("Run 'crs-toolchain self-update' to update")
		}
	},
}
