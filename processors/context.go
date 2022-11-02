// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"fmt"
	"io"
	"os"
)

type Context struct {
	rootDirectory      string
	rulesDirectory     string
	utilDirectory      string
	dataFilesDirectory string
	includeFiles       string
	singleRuleID       int
	singleChainOffset  bool
}

// NewContext creates a new processor context using the `rootDir` as the root directory.
func NewContext(rootDir string) *Context {
	// check if directory exists first
	_, err := os.Stat(rootDir)
	if err != nil {
		logger.Fatal().Err(err).Msgf("creating context: problem using %s as base directory.", rootDir)
	}
	ctx := &Context{
		rootDirectory:      rootDir,
		rulesDirectory:     rootDir + "/rules",
		utilDirectory:      rootDir + "/util",
		dataFilesDirectory: rootDir + "/util/regexp-assemble/data",
		includeFiles:       rootDir + "/util/regexp-assemble/data/include",
		singleRuleID:       0,
		singleChainOffset:  false,
	}
	return ctx
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
