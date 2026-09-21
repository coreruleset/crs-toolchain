// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/plugin"
)

var logger = log.With().Str("component", "cmd.plugin.install").Logger()

var (
	pluginsDir       string
	version          string
	force            bool
	requireSignature bool
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install NAME",
		Short: "Install a CRS plugin from the plugin registry",
		Long: `Resolve NAME against the published plugin registry, resolve a release tag,
download that release, and copy the plugin's files into the plugins directory.

Existing files are never overwritten unless --force is given.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := pluginsDir
			if targetDir == "" {
				targetDir = cmdContext.RootContext().PluginsDir()
			}

			result, err := plugin.Install(plugin.Options{
				Name:             args[0],
				Version:          version,
				PluginsDir:       targetDir,
				Force:            force,
				RequireSignature: requireSignature,
			})
			if err != nil {
				return err
			}

			report(cmd, cmdContext, targetDir, result)
			return nil
		},
	}

	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&pluginsDir, "plugins-dir", "",
		"Target directory to install into. Defaults to '<CRS_ROOT>/plugins'.")
	cmd.Flags().StringVar(&version, "version", "",
		"Release tag to install. Defaults to the newest release.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite files already present in the target directory.")
	cmd.Flags().BoolVar(&requireSignature, "require-signature", false,
		"Fail unless the release is signed. No registered plugin publishes signed releases yet, "+
			"so this always fails today.")
}

func report(cmd *cobra.Command, cmdContext *internal.CommandContext, targetDir string, result *plugin.Result) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Installed %s %s (%s) into %s\n", result.Name, result.Tag, result.Repository, targetDir)
	fmt.Fprintf(out, "  type: %s, status: %s, rule IDs: %d-%d\n",
		result.Type, result.Status, result.RuleIDRange.Start, result.RuleIDRange.End)
	fmt.Fprintf(out, "  digest: %s\n", result.Digest)

	if result.LuaWarning {
		warn(cmd, cmdContext, fmt.Sprintf("%s ships Lua scripts; it requires a Lua-enabled ModSecurity", result.Name))
	}
	for _, file := range result.OverlapWarnings {
		warn(cmd, cmdContext, fmt.Sprintf("%s's rule ID range overlaps existing file %s", result.Name, file))
	}
}

func warn(cmd *cobra.Command, cmdContext *internal.CommandContext, message string) {
	if cmdContext.Output == internal.GitHub {
		fmt.Fprintf(cmd.OutOrStdout(), "::warning ::%s\n", message)
		return
	}
	logger.Warn().Msg(message)
}
