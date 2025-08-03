package internal

import (
	"github.com/rs/zerolog"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

const defaultLogLevel = zerolog.InfoLevel

type CommandContext struct {
	rootContext           *context.Context
	Output                string
	LogLevel              zerolog.Level
	WorkingDirectory      string
	ConfigurationFileName string
}

func NewCommandContext(defaultWorkingDirectory string) *CommandContext {
	return &CommandContext{
		Output:                Text,
		LogLevel:              defaultLogLevel,
		WorkingDirectory:      defaultWorkingDirectory,
		ConfigurationFileName: "toolchain.yaml",
	}
}

func (c *CommandContext) RootContext() *context.Context {
	var ctx *context.Context
	if c.rootContext != nil {
		ctx = c.rootContext
	} else {
		ctx = context.New(c.WorkingDirectory, c.ConfigurationFileName)
		c.rootContext = ctx
	}
	return ctx
}
