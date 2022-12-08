// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// choreCmd represents the chore command
var choreCmd = createChoreCommand()

func init() {
	buildChoreCommand()
}

func createChoreCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "chore",
		Short: "Collection of chore commands",
		Args:  cobra.ExactArgs(1),
	}
}

func buildChoreCommand() {
	rootCmd.AddCommand(choreCmd)
}

func rebuildChoreCommand() {
	if choreCmd != nil {
		choreCmd.Parent().RemoveCommand(choreCmd)
	}

	utilCmd = createChoreCommand()
	buildChoreCommand()
}
