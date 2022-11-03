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
	rootDirectory         string
	rulesDirectory        string
	utilDirectory         string
	dataFilesDirectory    string
	includeFilesDirectory string
	includeFiles          string
	singleRuleID          int
	singleChainOffset     bool
}

// NewContext creates a new processor context using the `rootDir` as the root directory.
func NewContext(rootDir string) *Context {
	// check if directory exists first
	_, err := os.Stat(rootDir)
	if err != nil {
		logger.Fatal().Err(err).Msgf("creating context: problem using %s as base directory.", rootDir)
	}

	ctxt := context.New(rootDir)
	return &Context{
		rootDirectory:         ctxt.RootDirectory,
		rulesDirectory:        ctxt.RulesDirectory,
		utilDirectory:         ctxt.UtilDirectory,
		dataFilesDirectory:    ctxt.DataFilesDirectory,
		includeFilesDirectory: ctxt.IncludeFilesDirectory,
		singleRuleID:          0,
		singleChainOffset:     false,
	}
}

// Dump dumps the context to the passed io.Writer.
func (ctx *Context) Dump(w io.Writer) {
	fmt.Printf("Context: %v\n", ctx)
}

// DataDir returns the data directory. Used to find files that don't have an absolute path.
func (ctx *Context) DataDir() string {
	return ctx.dataFilesDirectory
}

// IncludeDir returns the include directory. Used to include files that don't have an absolute path.
func (ctx *Context) IncludeDir() string {
	return ctx.includeFiles
}

// RulesDir returns the rules directory.
func (ctx *Context) RulesDir() string {
	return ctx.rulesDirectory
}
