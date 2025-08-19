// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

// Generator defines the interface for generating different output formats from seclang rules
type Generator interface {
	// Generate creates the output for a single rule
	Generate(rule seclang.Rule) ([]byte, error)

	// GenerateFile creates the output for all rules in a file
	GenerateFile(filePath string) ([]byte, error)

	// GenerateMultiple creates the output for multiple rules
	GenerateMultiple(rules []seclang.Rule) ([]byte, error)

	// GetFileExtension returns the file extension for this generator's output format
	GetFileExtension() string

	// GetOutputFileName generates the output filename for a given rule
	GetOutputFileName(rule seclang.Rule) string
}

// GenerateContext provides context for generation operations
type GenerateContext struct {
	OutputDir string
	Rules     []seclang.Rule
}

// NewGenerateContext creates a new generation context
func NewGenerateContext(outputDir string) *GenerateContext {
	return &GenerateContext{
		OutputDir: outputDir,
		Rules:     []seclang.Rule{},
	}
}

// AddRule adds a rule to the generation context
func (gc *GenerateContext) AddRule(rule seclang.Rule) {
	gc.Rules = append(gc.Rules, rule)
}

// GenerateAll generates all rules using the provided generator and writes them to files
func (gc *GenerateContext) GenerateAll(generator Generator) error {
	if generator == nil {
		return fmt.Errorf("generator cannot be nil")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(gc.OutputDir, 0755); err != nil {
		return err
	}

	// Generate each rule individually
	for _, rule := range gc.Rules {
		data, err := generator.Generate(rule)
		if err != nil {
			return err
		}

		outputFile := filepath.Join(gc.OutputDir, generator.GetOutputFileName(rule))
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return err
		}
	}

	return nil
}

// GenerateSingleFile generates all rules into a single file using the provided generator
func (gc *GenerateContext) GenerateSingleFile(generator Generator, filename string) error {
	if generator == nil {
		return fmt.Errorf("generator cannot be nil")
	}

	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(gc.OutputDir, 0755); err != nil {
		return err
	}

	data, err := generator.GenerateMultiple(gc.Rules)
	if err != nil {
		return err
	}

	outputFile := filepath.Join(gc.OutputDir, filename)
	return os.WriteFile(outputFile, data, 0644)
}
