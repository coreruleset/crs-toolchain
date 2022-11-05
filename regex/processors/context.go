// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"fmt"
	"io"
	"os"

	"github.com/theseion/crs-toolchain/v2/context"
)

type Context struct {
	rootContext       *context.Context
	singleRuleID      int
	singleChainOffset bool
}

// NewContext creates a new processor context using the `rootDir` as the root directory.
func NewContext(rootDir string) *Context {
	// check if directory exists first
	_, err := os.Stat(rootDir)
	if err != nil {
		logger.Fatal().Err(err).Msgf("creating context: problem using %s as base directory.", rootDir)
	}

	return &Context{
		rootContext:       context.New(rootDir),
		singleRuleID:      0,
		singleChainOffset: false,
	}
}

// Dump dumps the context to the passed io.Writer.
func (ctx *Context) Dump(w io.Writer) {
	fmt.Printf("Context: %v\n", ctx)
}

// RootContext returns the the root context of the toolchain
func (ctx *Context) RootContext() *context.Context {
	return ctx.rootContext
}
