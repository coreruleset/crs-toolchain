// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

type CommandContext struct {
	OuterContext *internal.CommandContext
	Logger       *zerolog.Logger
	Id           string
	FileName     string
	ChainOffset  uint8
	UseStdin     bool
}

func NewCommandContext(cmdContext *internal.CommandContext, logger *zerolog.Logger) *CommandContext {
	return &CommandContext{
		OuterContext: cmdContext,
		Logger:       logger,
	}
}

func (c *CommandContext) RootContext() *context.Context {
	if c.OuterContext == nil {
		c.Logger.Fatal().Msg("No access to root context. Outer context is nil")
	}

	return c.OuterContext.RootContext()
}

// GetOutputDir returns the output directory from the command flags
func (c *CommandContext) GetOutputDir(cmd *cobra.Command) string {
	outputDir, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		// Fallback to default if flag is not available
		return "generate-output"
	}
	return outputDir
}
