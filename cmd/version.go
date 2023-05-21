// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	},
}
