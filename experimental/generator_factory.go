// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"fmt"

	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

// OutputFormat represents the available output formats
type OutputFormat string

const (
	YAMLFormat    OutputFormat = "yaml"
	JSONFormat    OutputFormat = "json"
	SeclangFormat OutputFormat = "seclang"
)

// GeneratorFactory manages different output format generators
type GeneratorFactory struct {
	generators map[OutputFormat]Generator
}

// NewGeneratorFactory creates a new generator factory with all available generators
func NewGeneratorFactory() *GeneratorFactory {
	factory := &GeneratorFactory{
		generators: make(map[OutputFormat]Generator),
	}

	// Register default generators
	factory.RegisterGenerator(YAMLFormat, seclang.NewYAMLGenerator())
	factory.RegisterGenerator(JSONFormat, seclang.NewJSONGenerator())
	factory.RegisterGenerator(SeclangFormat, seclang.NewSeclangGenerator())

	return factory
}

// RegisterGenerator registers a new generator for a specific format
func (gf *GeneratorFactory) RegisterGenerator(format OutputFormat, generator Generator) {
	gf.generators[format] = generator
}

// GetGenerator returns a generator for the specified format
func (gf *GeneratorFactory) GetGenerator(format OutputFormat) (Generator, error) {
	generator, exists := gf.generators[format]
	if !exists {
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
	return generator, nil
}

// GetSupportedFormats returns a list of supported output formats
func (gf *GeneratorFactory) GetSupportedFormats() []OutputFormat {
	formats := make([]OutputFormat, 0, len(gf.generators))
	for format := range gf.generators {
		formats = append(formats, format)
	}
	return formats
}

// IsFormatSupported checks if a format is supported
func (gf *GeneratorFactory) IsFormatSupported(format OutputFormat) bool {
	_, exists := gf.generators[format]
	return exists
}
