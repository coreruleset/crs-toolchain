package internal

import (
	"github.com/rs/zerolog"

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
