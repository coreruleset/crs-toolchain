// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// utilCmd represents the util command
var utilCmd = createUtilCommand()

func init() {
	buildUtilCommand()
}

func createUtilCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "util",
		Short: "Collection of utility commands",
		Args:  cobra.ExactArgs(1),
	}
}

func buildUtilCommand() {
	rootCmd.AddCommand(utilCmd)
}

func rebuildUtilCommand() {
	if utilCmd != nil {
		utilCmd.Parent().RemoveCommand(utilCmd)
	}

	utilCmd = createUtilCommand()
	buildUtilCommand()
}
