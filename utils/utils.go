// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

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
