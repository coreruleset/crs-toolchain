// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/configuration"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/util"
)

// fpFinderCommand represents the update command
var fpFinderCommand = createFpFinderCommand()
var extendedDictPath string
var englishDictionaryCommitRef string

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

			// CLI parameter is prioritized, if not provided config file is looked up
			// By default will be set to DefaultDictionaryCommitRef
			if strings.TrimSpace(englishDictionaryCommitRef) == "" {
				rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
				dictionaryContext := rootContext.Configuration().Sources.EnglishDictionary
				if dictionaryContext.WasCommitRefSet {
					englishDictionaryCommitRef = dictionaryContext.CommitRef
				} else {
					englishDictionaryCommitRef = configuration.DefaultDictionaryCommitRef
				}
			}

			if extendedDictPath != "" && !checkFilePath(extendedDictPath) {
				return fmt.Errorf("extended dictionary %s doesn't exist", extendedDictPath)
			}

			return fpFinder.FpFinder(filenameArg, extendedDictPath, englishDictionaryCommitRef)
		},
	}
}

func buildFpFinderCommand() {
	utilCmd.AddCommand(fpFinderCommand)
	fpFinderCommand.Flags().StringVarP(&extendedDictPath, "extended-dictionary", "e", "", "Absolute or relative path to the extended dictionary")
	fpFinderCommand.Flags().StringVarP(&englishDictionaryCommitRef, "english-dictionary-commit-ref", "c", "", "English dictionary commit ref from GitHub https://github.com/dwyl/english-words/blob/master/words_alpha.txt")
}

func checkFilePath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
