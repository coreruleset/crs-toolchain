// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/util"
)

// fpFinderCommand represents the update command
var fpFinderCommand = createFpFinderCommand()

func init() {
	buildFpFinderCommand()
}

func createFpFinderCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "fp-finder FILEPATH",
		Short: `False positive finder`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			return nil
		}),
		RunE: func(cmd *cobra.Command, args []string) error {
			fpFinder := util.NewFpFinder()

			sortEnabled, err := cmd.Flags().GetBool("sort")
			if err != nil {
				logger.Error().Err(err).Msg("Failed to read value for 'sort' flag")
				return err
			}

			uniqEnabled, err := cmd.Flags().GetBool("uniq")
			if err != nil {
				logger.Error().Err(err).Msg("Failed to read value for 'uniq' flag")
				return err
			}

			filenameArg := args[0]
			if !checkFilePath(filenameArg) {
				return fmt.Errorf("file %s doesn't exist", filenameArg)
			}

			return fpFinder.FpFinder(filenameArg, sortEnabled, uniqEnabled)
		},
	}

}

func buildFpFinderCommand() {
	utilCmd.AddCommand(fpFinderCommand)
	fpFinderCommand.Flags().BoolP("sort", "s", false, "Sort the output alphabetically")
	fpFinderCommand.Flags().BoolP("uniq", "u", false, "Remove duplicated value from the output")
}

func checkFilePath(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}
