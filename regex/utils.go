package regex

import (
	"fmt"
	"strings"
)

func IsEscaped(input string, position int) bool {
	escapeCounter := 0
	for backtrackIndex := position - 1; backtrackIndex >= 0; backtrackIndex-- {
		if input[backtrackIndex] != '\\' {
			break
		}
		escapeCounter++
	}
	return escapeCounter%2 != 0
}

// NegativeLookahead builds the regex.
func NegativeLookahead(strs []string, prefix, suffix string) string {
	var result strings.Builder

	result.WriteString(set(strs, 0, "^"))

	var commonStr string
	var followingChars map[rune]struct{}
	followingChars = make(map[rune]struct{})

	// Only find common string if we have more than one
	if len(strs) > 1 {
		commonStr = commonPrefix(strs)

		// Collect all characters after the common substring from every string
		for _, s := range strs {
			if len(s) > len(commonStr) && strings.HasPrefix(s, commonStr) {
				followingChars[rune(s[len(commonStr)])] = struct{}{}
			}
		}
	}

	// Add the common string to the regex to prevent accidental matching
	if len(commonStr) > 0 {
		if len(commonStr) > 1 {
			result.WriteString("|(?:" + prepare(commonStr, 1) + ")")
		}
		result.WriteString("|(?:" + commonStr + "[^" + flatten(followingChars) + "]" + ")")
	}

	// Add remaining parts of the strings
	for _, s := range strs {
		var g string
		if len(commonStr) > 0 {
			g = prepare(s, len(commonStr)+1)
		} else {
			g = prepare(s, 1)
		}

		// Add OR boolean if necessary
		if len(g) > 0 {
			result.WriteString("|")
		}
		result.WriteString(g)
	}

	// Print the final regex
	return fmt.Sprintf("%s(?:%s)%s", prefix, result.String(), suffix)
}

// commonPrefix returns the longest common prefix of a list of strings.
func commonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	s1 := strs[0]
	s2 := strs[len(strs)-1]
	for i, c := range s1 {
		if c != rune(s2[i]) {
			return s1[:i]
		}
	}
	return s1
}

// flatten concatenates the keys of the map into a string.
func flatten(dict map[rune]struct{}) string {
	var result string
	for key := range dict {
		result += string(key)
	}
	return result
}

// set returns a character set containing unique characters across all strings at the given index.
func set(strings []string, index int, flags string) string {
	dict := make(map[rune]struct{})
	for _, s := range strings {
		// Continue if the index exceeds the string length.
		if index >= len(s) {
			continue
		}
		dict[rune(s[index])] = struct{}{}
	}
	return "[" + flags + flatten(dict) + "]"
}

// prepare converts a string for negative lookaheads emulation.
func prepare(s string, offset int) string {
	var result strings.Builder
	for i := offset; i < len(s); i++ {
		for j := 0; j <= i; j++ {
			if j == i {
				result.WriteString("[^" + string(s[j]) + "]")
			} else {
				result.WriteString(string(s[j]))
			}
		}
		if i != len(s)-1 {
			result.WriteString("|")
		}
	}
	return result.String()
}

// func main() {
// 	// Parse command-line arguments
// 	var prefix, suffix string
// 	flag.StringVar(&prefix, "prefix", "", "sets a prefix for the resulting regex")
// 	flag.StringVar(&suffix, "suffix", "", "sets a suffix for the resulting regex")
//
// 	// args[0] onwards will be the strings to convert into a negative lookahead
// 	flag.Parse()
//
// 	// The remaining arguments after flags are the strings
// 	strings := flag.Args()
//
// 	// Run the program logic
// 	run(strings, prefix, suffix)
// }
