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

var logger = log.With().Str("component", "copyright-update").Logger()

// CopyrightUpdate updates the copyright portion on the rules files to the provided year and version.
func CopyrightUpdate(ctxt *context.Context, version string, year string) {
	err := filepath.WalkDir(ctxt.RulesDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// abort
			return err
		}
		if d.IsDir() {
			// continue
			return nil
		}
		if strings.HasSuffix(d.Name(), ".conf") {
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

// Ideally we have support in the future for a proper parser file so we can use that to change it
// in a more elegant way. Right now we just match strings.
func updateRules(version string, year string, contents []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Split(bufio.ScanLines)
	output := new(bytes.Buffer)
	writer := bufio.NewWriter(output)
	for scanner.Scan() {
		line := scanner.Text()
		replaceVersion := fmt.Sprintf("${1}%s", version)
		line = regex.CRSVersionRegex.ReplaceAllString(line, replaceVersion)
		replaceYear := fmt.Sprintf("${1}%s${3}", year)
		line = regex.CRSCopyrightYear.ReplaceAllString(line, replaceYear)

		if _, err := writer.WriteString(line); err != nil {
			return nil, err
		}
		if _, err := writer.WriteRune('\n'); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	outputBytes := output.Bytes()
	// remove the superfluous newline character
	return outputBytes[:len(outputBytes)-1], nil
}
