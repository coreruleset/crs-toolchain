# crs-toolchain

[![Regression Tests](https://github.com/coreruleset/crs-toolchain/actions/workflows/regression.yml/badge.svg)](https://github.com/coreruleset/crs-toolchain/actions/workflows/regression.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coreruleset/crs-toolchain/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coreruleset/crs-toolchain)

The CRS developer's utility belt. The documentation lives at [coreruleset.org](https://coreruleset.org/docs/development/crs_toolchain/).

## Installation

### Homebrew (macOS and Linux)

`crs-toolchain` can be installed on macOS and Linux via [Homebrew](https://brew.sh) using the [CRS tap](https://github.com/coreruleset/homebrew-tap):

```shell
brew tap coreruleset/tap
brew install crs-toolchain
```

To upgrade to the latest version:

```shell
brew upgrade crs-toolchain
```

### Linux

Download the latest release archive for your architecture from the [releases page](https://github.com/coreruleset/crs-toolchain/releases), then extract and install the binary:

```shell
# Replace <version> and <arch> with the appropriate values (e.g. 1.0.0 and amd64)
curl -sSL https://github.com/coreruleset/crs-toolchain/releases/download/v<version>/crs-toolchain_<version>_linux_<arch>.tar.gz | tar -xz crs-toolchain
sudo mv crs-toolchain /usr/local/bin/
```

Alternatively, `.deb` and `.rpm` packages are available on the [releases page](https://github.com/coreruleset/crs-toolchain/releases):

```shell
# Debian/Ubuntu (.deb)
sudo dpkg -i crs-toolchain_<version>_linux_<arch>.deb

# RHEL/Fedora (.rpm)
sudo rpm -i crs-toolchain_<version>_linux_<arch>.rpm
```

### Install with Go

If you have Go 1.19+ installed, you can install `crs-toolchain` directly:

```shell
go install github.com/coreruleset/crs-toolchain/v2@latest
```

Make sure your Go bin directory (typically `~/go/bin`) is on your `PATH`.

## Usage Examples

Run from the CRS repository root (or provide `--directory`):

```shell
crs-toolchain --directory /path/to/coreruleset/coreruleset regex compare 932100
```

### Regex workflow

```shell
# Generate regex for one assembly file
crs-toolchain regex generate 932100

# Generate regex from stdin input
cat regex-assembly/REQUEST-932-APPLICATION-ATTACK-RCE/932100.ra | crs-toolchain regex generate -

# Compare one rule against generated output
crs-toolchain regex compare 932100

# Compare all rules
crs-toolchain regex compare --all

# Format one regex-assembly file
crs-toolchain regex format 932100

# Check formatting without writing changes
crs-toolchain regex format --all --check

# Update one rule from assembly source
crs-toolchain regex update 932100

# Update multiple rules/files in one call
crs-toolchain regex update 932100 933100-chain1.ra

# Update all rules from assembly files
crs-toolchain regex update --all
```

### Utility commands

```shell
# Filter likely false-positive words from stdin
printf "select\nxqz\n" | crs-toolchain util fp-finder -

# Use an additional dictionary
crs-toolchain util fp-finder ./candidate_words.txt --extended-dictionary ./words-extra.txt

# Check test numbering for one rule
crs-toolchain util renumber-tests 932100 --check

# Renumber all tests
crs-toolchain util renumber-tests --all
```

### Chore commands

```shell
# Create release branch from a specific source ref
crs-toolchain chore release --source-ref main

# Refresh copyright headers
crs-toolchain chore update-copyright --year 2026

# Create monthly chat agenda (requires GitHub token and wiki access)
crs-toolchain chore create-agenda
```

### Shell completion and output modes

```shell
# Generate shell completion
crs-toolchain completion zsh > ~/.zfunc/_crs-toolchain

# Use GitHub Actions-friendly output and debug logs
crs-toolchain --output github --log-level debug regex format --all --check
```

### Self-Update

Once `crs-toolchain` is installed (via any method), you can update to the latest version using the built-in self-update command:

```shell
crs-toolchain util self-update
```

This will automatically download and replace the current binary with the latest release for your platform.
