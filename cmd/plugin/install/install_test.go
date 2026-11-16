// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

type installCmdTestSuite struct {
	suite.Suite
}

func TestRunInstallCmdTestSuite(t *testing.T) {
	suite.Run(t, new(installCmdTestSuite))
}

func (s *installCmdTestSuite) TestFlagsRegistered() {
	cmd := New(internal.NewCommandContext(s.T().TempDir()))

	for _, name := range []string{PluginsDirFlag, VersionFlag, ForceFlag, RequireSignatureFlag} {
		s.NotNil(cmd.Flags().Lookup(name), "flag %q not registered", name)
	}
}

func (s *installCmdTestSuite) TestFlagsParse() {
	cmd := New(internal.NewCommandContext(s.T().TempDir()))

	s.Require().NoError(cmd.ParseFlags([]string{
		"--" + PluginsDirFlag, "/tmp/plugins",
		"--" + VersionFlag, "v1.2.3",
		"--" + ForceFlag,
		"--" + RequireSignatureFlag,
	}))

	s.Equal("/tmp/plugins", pluginsDir)
	s.Equal("v1.2.3", version)
	s.True(force)
	s.True(requireSignature)
}
