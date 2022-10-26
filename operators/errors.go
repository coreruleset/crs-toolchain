package operators

import "fmt"

type NestingError struct {
	line  string
	depth int8
}

func (n *NestingError) Error() string {
	return fmt.Sprintf("Nesting error on line %s, nesting level %d", n.line, n.depth)
}
