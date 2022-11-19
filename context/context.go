// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package context

type Context struct {
	rootDirectory                string
	rulesDirectory               string
	dataFilesDirectory           string
	includeFilesDirectory        string
	regressionTestFilesDirectory string
}

func New(rootDir string) *Context {
	return &Context{
		rootDirectory:                rootDir,
		rulesDirectory:               rootDir + "/rules",
		dataFilesDirectory:           rootDir + "/regex-assembly",
		includeFilesDirectory:        rootDir + "/regex-assembly/include",
		regressionTestFilesDirectory: rootDir + "/tests/regression/tests",
	}
}

// RootDir returns the root of the CRS directory structure.
func (ctx *Context) RootDir() string {
	return ctx.rootDirectory
}

// DataDir returns the 'data' directory.
func (ctx *Context) DataDir() string {
	return ctx.dataFilesDirectory
}

// IncludeDir returns the 'include' directory. Used to include files that don't have an absolute path.
func (ctx *Context) IncludeDir() string {
	return ctx.includeFilesDirectory
}

// RulesDir returns the 'rules' directory.
func (ctx *Context) RulesDir() string {
	return ctx.rulesDirectory
}

// RegressionTestsDir returns the 'tests' directory of regression tests.
func (ctx *Context) RegressionTestsDir() string {
	return ctx.regressionTestFilesDirectory
}
