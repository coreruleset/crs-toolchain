package format

import "fmt"

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
