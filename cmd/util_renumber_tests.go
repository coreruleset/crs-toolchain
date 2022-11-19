// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/context"
	"github.com/coreruleset/crs-toolchain/util"
)

// renumberTestsCommand represents the update command
var renumberTestsCommand = createRenumberTestsCommand()

func init() {
	buildRenumberTestsCommand()
}

func createRenumberTestsCommand() *cobra.Command {

	return &cobra.Command{
		Use:   "renumber-tests",
		Short: "Renumber all CRS tests, so that they are sequential in every file",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			ctxt := context.New(rootValues.workingDirectory.String())
			util.RenumberTests(ctxt)
		},
	}

}

func buildRenumberTestsCommand() {
	utilCmd.AddCommand(renumberTestsCommand)
}

func rebuildRenumberTestsCommand() {
	if renumberTestsCommand != nil {
		renumberTestsCommand.Parent().RemoveCommand(renumberTestsCommand)
	}

	renumberTestsCommand = createRenumberTestsCommand()
	buildRenumberTestsCommand()
}
