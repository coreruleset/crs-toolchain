// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/theseion/crs-toolchain/v2/chore"
	"github.com/theseion/crs-toolchain/v2/context"
	"time"
)

// choreCmd represents the chore command
var choreCopyrightUpdateCmd = createChoreCopyrightUpdateCommand()
var copyrightVariables struct {
	Version string
	Year    int
}

func init() {
	buildChoreCopyrightUpdateCommand()
}

func createChoreCopyrightUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "copyright-update",
		Short: "Updates the copyright on every rule file",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			ctxt := context.New(rootValues.workingDirectory.String())
			chore.CopyrightUpdate(ctxt, "the version", time.Now().Year())
		},
	}
}

func buildChoreCopyrightUpdateCommand() {
	choreCmd.AddCommand(choreCopyrightUpdateCmd)
}

func rebuildChoreCopyrightUpdateCommand() {
	if choreCopyrightUpdateCmd != nil {
		choreCopyrightUpdateCmd.Parent().RemoveCommand(choreCopyrightUpdateCmd)
	}

	utilCmd = createChoreCopyrightUpdateCommand()
	buildChoreCopyrightUpdateCommand()
}
