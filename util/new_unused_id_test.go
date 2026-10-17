// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

type newUnusedIdTestSuite struct {
	suite.Suite
	ctxt *context.Context
}

func TestNewUnusedIdTestSuite(t *testing.T) {
	suite.Run(t, new(newUnusedIdTestSuite))
}

func (s *newUnusedIdTestSuite) SetupTest() {
	root := s.T().TempDir()
	s.Require().NoError(os.MkdirAll(filepath.Join(root, "rules"), 0755))
	s.ctxt = context.New(root, "toolchain.yaml")
}

func (s *newUnusedIdTestSuite) writeFile(name string, content string) {
	s.Require().NoError(os.WriteFile(filepath.Join(s.ctxt.RootDir(), name), []byte(content), 0644))
}

func (s *newUnusedIdTestSuite) TestUnknownRange() {
	s.writeFile("rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", `SecRule ARGS "@rx a" "id:942100,phase:2"`)
	_, err := NewUnusedId("960", s.ctxt)
	s.EqualError(err, "no rules found in range 960")
}

func (s *newUnusedIdTestSuite) TestSkipsFlowControlRules() {
	s.writeFile("rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942013,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
`)
	id, err := NewUnusedId("942", s.ctxt)
	s.Require().NoError(err)
	s.Equal("942100", id)
}

func (s *newUnusedIdTestSuite) TestNextAfterHighestIgnoringGaps() {
	// 942110 was removed; it must not be reused.
	s.writeFile("rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", `SecRule ARGS "@rx a" "id:942100,phase:2"
SecRule ARGS "@rx b" "id:942120,phase:2"
SecRule ARGS "@rx c" "id:942121,phase:2"
`)
	id, err := NewUnusedId("942", s.ctxt)
	s.Require().NoError(err)
	s.Equal("942130", id)
}

func (s *newUnusedIdTestSuite) TestIgnoresOtherRanges() {
	s.writeFile("rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", `SecRule ARGS "@rx a" "id:942500,phase:2"
SecRule ARGS "@rx b" "id:941100,phase:2,ctl:ruleRemoveById=942600"
`)
	id, err := NewUnusedId("941", s.ctxt)
	s.Require().NoError(err)
	s.Equal("941110", id)
}

func (s *newUnusedIdTestSuite) TestIdFormats() {
	s.writeFile("rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", "SecRule A \"@rx a\" \"id: 930100\"\n"+
		"SecRule A \"@rx a\" \"id:'930110'\"\n"+
		"SecRule A \"@rx a\" \"id:\\\"930120\\\"\"\n"+
		"SecRule A \"@rx a\" \\\n    \"id:930130,\\\n    phase:1\"\n")
	id, err := NewUnusedId("930", s.ctxt)
	s.Require().NoError(err)
	s.Equal("930140", id)
}

func (s *newUnusedIdTestSuite) TestSetupAndExampleFiles() {
	s.writeFile("crs-setup.conf.example", "#SecAction \"id:900990,phase:1\"\n")
	s.writeFile("rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example", "#SecRule A \"@rx a\" \"id:901500\"\n")

	_, err := NewUnusedId("900", s.ctxt)
	s.EqualError(err, "no unused IDs left in range 900")

	id, err := NewUnusedId("901", s.ctxt)
	s.Require().NoError(err)
	s.Equal("901510", id)
}

func (s *newUnusedIdTestSuite) TestInvalidRange() {
	for _, prefix := range []string{"92", "9200", "abc", "-12", "+12", "9 2"} {
		_, err := NewUnusedId(prefix, s.ctxt)
		s.EqualError(err, "range must be exactly 3 digits, got: "+prefix)
	}
}
