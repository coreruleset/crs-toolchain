// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import "regexp"

type Processor struct {
	ctx          *Context
	commentRegex *regexp.Regexp
	lines        []string
}

type IProcessor interface {
	HasBody() bool
	ProcessLine(line string)
	Complete() []string
}
