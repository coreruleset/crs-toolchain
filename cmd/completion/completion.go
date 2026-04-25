// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package completion

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var logger = log.With().Str("component", "cmd.chore.update_copyright").Logger()

func New() *cobra.Command {
	return createCompletionCommand()
}

func createCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:                   "completion [bash|zsh|fish|powershell]",
		Short:                 "Generate completion script for shell",
		Long:                  "Completion files allow you to repeatedly press tab key to show completion for all supported commands",
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1)),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			switch args[0] {
			case "bash":
				err = cmd.Root().GenBashCompletion(os.Stdout)
				if err != nil {
					logger.Fatal().Err(err).Send()
				}
			case "zsh":
				err = cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				err = cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				err = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			if err != nil {
				logger.Fatal().Err(err).Send()
			}
		},
	}
}
