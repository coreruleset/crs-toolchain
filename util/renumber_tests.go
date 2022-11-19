// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/crs-toolchain/context"
	"github.com/coreruleset/crs-toolchain/regex"
)

var logger = log.With().Str("component", "renumber-tests").Logger()

func RenumberTests(ctxt *context.Context) {
	err := filepath.WalkDir(ctxt.RegressionTestsDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// abort
			return err
		}
		if d.IsDir() {
			// continue
			return nil
		}

		if err := processFile(path); err != nil {
			// abort
			return err
		}
		// continue
		return nil
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to renumber tests")
	}
}

func processFile(filePath string) error {
	ruleId := path.Base(filePath)[0:6]
	logger.Info().Msgf("Processing %s", ruleId)

	contents, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	output, err := processYaml(ruleId, contents)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, output, fs.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func processYaml(ruleId string, contents []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Split(bufio.ScanLines)
	output := new(bytes.Buffer)
	writer := bufio.NewWriter(output)
	index := 0
	for scanner.Scan() {
		line := scanner.Text()
		matches := regex.TestTitleRegex.FindStringSubmatch(line)
		if matches != nil {
			index++
			line = fmt.Sprint(matches[1], ruleId, "-", index)
		}

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
