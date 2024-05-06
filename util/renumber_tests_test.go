// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type renumberTestsTestSuite struct {
	suite.Suite
}

func (s *renumberTestsTestSuite) SetupTest() {
}

func TestRunRenumberTestsTestSuite(t *testing.T) {
	suite.Run(t, new(renumberTestsTestSuite))
}

func (s *renumberTestsTestSuite) TestRenumberTests_Setid() {
	contents := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: bapedibupi
    desc: "test 1"
  - test_id: "pine apple"
    desc: "test 2"
`
	expected := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: 1
    desc: "test 1"
  - test_id: 2
    desc: "test 2"
`
	out, err := NewTestRenumberer().processYaml([]byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}

func (s *renumberTestsTestSuite) TestRenumberTests_RemoveSuperfluousNewLinesAtEof() {
	contents := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: bapedibupi
    desc: "test 1"
  - test_id: "pine apple"
    desc: "test 2"


`
	expected := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: 1
    desc: "test 1"
  - test_id: 2
    desc: "test 2"
`
	out, err := NewTestRenumberer().processYaml([]byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}

func (s *renumberTestsTestSuite) TestRenumberTests_AddMissingNewLineAtEof() {
	contents := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: bapedibupi
    desc: "test 1"
  - test_id: "pine apple"
    desc: "test 2"`
	expected := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: 1
    desc: "test 1"
  - test_id: 2
    desc: "test 2"
`
	out, err := NewTestRenumberer().processYaml([]byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}

func (s *renumberTestsTestSuite) TestRenumberTests_TrimSpaceOnTrailingLines() {
	contents := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: bapedibupi
    desc: "test 1"
  - test_id: "pine apple"
    desc: "test 2"
     
       
   `
	expected := `---
meta:
  enabled: true
  name: 123456.yaml
tests:
  - test_id: 1
    desc: "test 1"
  - test_id: 2
    desc: "test 2"
`
	out, err := NewTestRenumberer().processYaml([]byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}
