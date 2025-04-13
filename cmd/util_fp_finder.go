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
var extendedDictPath string
var englishDictionaryCommitHash string

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
			filenameArg := args[0]
			if !checkFilePath(filenameArg) {
				return fmt.Errorf("file %s doesn't exist", filenameArg)
			}

			if extendedDictPath != "" && !checkFilePath(extendedDictPath) {
				return fmt.Errorf("extended dictionary %s doesn't exist", extendedDictPath)
			}

			return fpFinder.FpFinder(filenameArg, extendedDictPath, englishDictionaryCommitHash)
		},
	}

}

func buildFpFinderCommand() {
	utilCmd.AddCommand(fpFinderCommand)
	fpFinderCommand.Flags().StringVarP(&extendedDictPath, "extended-dictionary", "e", "", "Absolute or relative path to the extended dictionary")
	fpFinderCommand.Flags().StringVarP(&englishDictionaryCommitHash, "english-dictionary-commit-hash", "c", "8179fe68775df3f553ef19520db065228e65d1d3", "English dictionary commit hash from Github")
}

func checkFilePath(path string) bool {
	_, err := os.Stat(path)
	os.IsNotExist(err)
	return err == nil
}
