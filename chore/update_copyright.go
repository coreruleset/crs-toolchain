package chore

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/crs-toolchain/context"
	"github.com/coreruleset/crs-toolchain/regex"
)

var logger = log.With().Str("component", "update-copyright").Logger()

// UpdateCopyright updates the copyright portion of the rules files to the provided year and version.
func UpdateCopyright(ctxt *context.Context, version string, year string) {
	err := filepath.WalkDir(ctxt.RootDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// abort
			return err
		}
		if d.IsDir() {
			// continue
			return nil
		}
		if strings.HasSuffix(d.Name(), ".conf") || strings.HasSuffix(d.Name(), ".example") {
			if err := processFile(path, version, year); err != nil {
				// abort
				return err
			}
		}
		// continue
		return nil
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to update copyright")
	}
}

func processFile(filePath string, version string, year string) error {
	logger.Info().Msgf("Processing %s", filePath)

	contents, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	output, err := updateRules(version, year, contents)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, output, fs.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

// Ideally we have support in the future for a proper parser file, so we can use that to change it
// in a more elegant way. Right now we just match strings.
func updateRules(version string, year string, contents []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Split(bufio.ScanLines)
	output := new(bytes.Buffer)
	writer := bufio.NewWriter(output)
	replaceVersion := fmt.Sprintf("${1}%s", version)
	replaceYear := fmt.Sprintf("${1}%s${3}", year)
	for scanner.Scan() {
		line := scanner.Text()
		line = regex.CRSVersionRegex.ReplaceAllString(line, replaceVersion)
		line = regex.CRSCopyrightYearRegex.ReplaceAllString(line, replaceYear)

		if _, err := writer.WriteString(line); err != nil {
			return nil, err
		}
		if _, err := writer.WriteRune('\n'); err != nil {
			return nil, err
		}
	}

	if err := writer.Flush(); err != nil {
		return nil, err
	}
	outputBytes := output.Bytes()
	// if the file was empty, we didn't change anything and we're done
	if len(outputBytes) == 0 {
		return outputBytes, nil
	}
	// remove the superfluous newline character
	return outputBytes[:len(outputBytes)-1], nil
}
