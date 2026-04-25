// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-getter/v2"
)

func IsEscaped(input string, position int) bool {
	escapeCounter := 0
	for backtrackIndex := position - 1; backtrackIndex >= 0; backtrackIndex-- {
		if input[backtrackIndex] != '\\' {
			break
		}
		escapeCounter++
	}
	return escapeCounter%2 != 0
}

func DownloadFile(filepath, url string) error {
	request := &getter.Request{
		Src:     url,
		Dst:     filepath,
		GetMode: getter.ModeAny,
	}
	client := &getter.Client{
		Getters: []getter.Getter{
			new(getter.HttpGetter),
		},
	}

	_, err := client.Get(context.Background(), request)
	return err
}

func GetCacheFilePath(fileName string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	crsToolchainDir := filepath.Join(homeDir, ".crs-toolchain")

	// Create ~/.crs-toolchain folder if it doesn't exist
	if _, err := os.Stat(crsToolchainDir); os.IsNotExist(err) {
		if err := os.MkdirAll(crsToolchainDir, 0755); err != nil {
			return "", err
		}
	}

	return filepath.Join(crsToolchainDir, fileName), nil
}
