# crs-toolchain

[![Regression Tests](https://github.com/coreruleset/crs-toolchain/actions/workflows/regression.yml/badge.svg)](https://github.com/coreruleset/crs-toolchain/actions/workflows/regression.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coreruleset/crs-toolchain/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coreruleset/crs-toolchain)

The CRS developer's utility belt. The documentation lives at [coreruleset.org](https://coreruleset.org/docs/development/crs_toolchain/).

## Installation

### Homebrew (macOS)

`crs-toolchain` can be installed on macOS via [Homebrew](https://brew.sh) using the [CRS tap](https://github.com/coreruleset/homebrew-tap):

```shell
brew tap coreruleset/tap
brew install --cask crs-toolchain
```

To upgrade to the latest version:

```shell
brew upgrade --cask crs-toolchain
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