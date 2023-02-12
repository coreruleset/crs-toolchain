// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type selfUpdateTestSuite struct {
	suite.Suite
}

func (s *selfUpdateTestSuite) SetupTest() {
	rebuildSelfUpdateCommand()
}

func (s *selfUpdateTestSuite) TearDownTest() {
}

func TestRunSelfUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(selfUpdateTestSuite))
}
