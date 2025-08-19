// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	buildInternal "github.com/coreruleset/crs-toolchain/v2/cmd/generate/internal"
	"github.com/coreruleset/crs-toolchain/v2/cmd/generate/seclang"
	"github.com/coreruleset/crs-toolchain/v2/cmd/generate/yaml"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

var logger = log.With().Str("component", "cmd.generate").Logger()

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Commands that generate artifacts from seclang rules",
		Long: `The commands in this group generate various artifacts from seclang rules (.conf files).
For example, they can generate YAML files from seclang rules for documentation or
configuration purposes.`,
	}

	// Add persistent flags for the generate command
	cmd.PersistentFlags().StringP("output-dir", "t", "generate-output", "Output directory for generated files")

	buildCmdContext := buildInternal.NewCommandContext(cmdContext, &logger)
	cmd.AddCommand(
		yaml.New(buildCmdContext),
		seclang.New(buildCmdContext),
	)

	return cmd
}
