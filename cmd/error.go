package cmd

import "errors"

var (
	ErrUpdateCopyrightWithoutVersion = errors.New("version is needed to update the copyright. You can use 'git describe --tags' if using git")
)
