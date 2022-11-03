// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package context

type Context struct {
	RootDirectory                string
	RulesDirectory               string
	UtilDirectory                string
	DataFilesDirectory           string
	IncludeFilesDirectory        string
	RegressionTestFilesDirectory string
}

func New(rootDir string) *Context {
	return &Context{
		RootDirectory:                rootDir,
		RulesDirectory:               rootDir + "/rules",
		UtilDirectory:                rootDir + "/util",
		DataFilesDirectory:           rootDir + "/util/regexp-assemble/data",
		IncludeFilesDirectory:        rootDir + "/util/regexp-assemble/data/include",
		RegressionTestFilesDirectory: rootDir + "/tests/regression/tests",
	}
}
