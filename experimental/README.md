# Experimental Features

This directory contains experimental features that are being developed for the CRS Toolchain. These features may change or be removed in future releases.

## Generator Interface

The Generator interface provides an extensible way to generate different output formats from seclang rules. This is an experimental feature that allows for easy addition of new output formats.

### Files

- `generator.go` - Defines the Generator interface and GenerateContext
- `generator_factory.go` - Provides a factory pattern for managing different generators

### Usage

The Generator interface is used by the `generate` command to create different output formats:

- **YAML**: `./crs-toolchain generate yaml [RULE_ID]`
- **Seclang**: `./crs-toolchain generate seclang [YAML_FILE]`

### Adding New Generators

To add a new generator:

1. Implement the `Generator` interface in the `internal/seclang` package
2. Register the generator in the factory in `generator_factory.go`
3. Add a new subcommand to the `generate` command

### Interface

```go
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
```

### Supported Formats

- **YAML**: Generates CRSLang YAML format
- **JSON**: Generates JSON format (example implementation)
- **Seclang**: Generates seclang format (reverse operation)

### Status

This is an experimental feature. The interface and implementation may change based on feedback and requirements.
