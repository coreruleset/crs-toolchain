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
