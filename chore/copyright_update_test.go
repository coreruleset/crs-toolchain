// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package chore

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type copyrightUpdateTestsTestSuite struct {
	suite.Suite
}

func (s *copyrightUpdateTestsTestSuite) SetupTest() {
}

func TestRunCopyrightUpdateTestsTestSuite(t *testing.T) {
	suite.Run(t, new(copyrightUpdateTestsTestSuite))
}

func (s *copyrightUpdateTestsTestSuite) TestCopyrightUpdateTests_SetVersion() {
	contents := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.0-rc1
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#wiki-SecComponentSignature
#
SecComponentSignature "OWASP_CRS/4.0.0-rc1"`
	expected := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.9.1.22
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2042 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#wiki-SecComponentSignature
#
SecComponentSignature "OWASP_CRS/4.0.0-rc1"`
	out, err := updateRules("9.1.22", 2042, []byte(contents))
	s.NoError(err)

	s.Equal(expected, string(out))
}
