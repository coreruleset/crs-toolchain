# Test Data

This directory contains test data files used by the test suites.

## Structure

- `test-rules/` - Contains seclang rule files for testing the YAML generation functionality
  - `test-rule.conf` - Sample seclang rules for testing parser functionality

## Usage

The test files are used by:
- `internal/seclang/parser_test.go` - Tests for the seclang parser
- `cmd/build/yaml/yaml_test.go` - Tests for the yaml generation command

## Adding New Test Files

When adding new test files:
1. Place them in the appropriate subdirectory
2. Update this README to document the new files
3. Ensure tests handle missing files gracefully (use `t.Skip()` if appropriate)
