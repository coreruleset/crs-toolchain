package cmd

import (
	"errors"
	"fmt"
)

var (
	ErrUpdateCopyrightWithoutVersion = errors.New("version is needed to update the copyright. You can use 'git describe --tags' if using git")
)

type UnformattedFileError struct {
	filePath string
}

func (u *UnformattedFileError) Error() string {
	if u.HasPathInfo() {
		return fmt.Sprintf("File not properly formatted: %s", u.filePath)
	}

	return "One or more files are not properly formatted"
}

func (u *UnformattedFileError) HasPathInfo() bool {
	return u.filePath != ""
}
