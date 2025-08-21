// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package fpFinder

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/util"
)

var extendedDictPath string
var englishDictionaryCommitRef string

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fp-finder FILEPATH | -",
		Short: `False positive finder`,
		Long: `Takes a list of words from FILEPATH (one word per line) and eliminates all words that
can be found in an English dictionary, since these are likely to cause false positives.

The special token '-' will cause the script to accept input
from stdin instead.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), cobra.MinimumNArgs(1), func(cmd *cobra.Command, args []string) error {
			return nil
		}),
		RunE: func(cmd *cobra.Command, args []string) error {
			fpFinder := util.NewFpFinder()
			filenameArg := args[0]
			if filenameArg != "-" && !checkFilePath(filenameArg) {
				return fmt.Errorf("file %s doesn't exist", filenameArg)
			}

			if extendedDictPath != "" && !checkFilePath(extendedDictPath) {
				return fmt.Errorf("extended dictionary %s doesn't exist", extendedDictPath)
			}

			return fpFinder.FpFinder(filenameArg, extendedDictPath, englishDictionaryCommitRef)
		},
	}

	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&extendedDictPath, "extended-dictionary", "e", "", "Absolute or relative path to the extended dictionary")
}

func checkFilePath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
