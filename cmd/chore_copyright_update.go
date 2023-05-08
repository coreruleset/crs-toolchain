// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/chore"
	"github.com/coreruleset/crs-toolchain/context"
)

var choreCopyrightUpdateCmd = createChoreCopyrightUpdateCommand()
var copyrightVariables struct {
	Version string
	Year    string
}

func init() {
	buildChoreCopyrightUpdateCommand()
}

func createChoreCopyrightUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "copyright-update",
		Short: "Updates the copyright on every rule file",
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			chore.CopyrightUpdate(rootContext, copyrightVariables.Version, copyrightVariables.Year)
		},
	}
}

func buildChoreCopyrightUpdateCommand() {
	choreCmd.AddCommand(choreCopyrightUpdateCmd)
	choreCopyrightUpdateCmd.Flags().StringVarP(&copyrightVariables.Year, "year", "y", strconv.Itoa(time.Now().Year()), "Year, example: 2023. Default: current year.")
	choreCopyrightUpdateCmd.Flags().StringVarP(&copyrightVariables.Version, "version", "v", "CRS v10.0.1", "Add this text as the version to the file.")
}

func rebuildChoreCopyrightUpdateCommand() {
	if choreCopyrightUpdateCmd != nil {
		choreCopyrightUpdateCmd.Parent().RemoveCommand(choreCopyrightUpdateCmd)
	}

	choreCopyrightUpdateCmd = createChoreCopyrightUpdateCommand()
	buildChoreCopyrightUpdateCommand()
}
