package validation

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const backSlash = byte('\\')
const closingBrace = byte('}')
const openingBracket = byte('[')
const closingBracket = byte(']')

var unicodeHexEscapePrefix = []byte("\\x{")

func ValidateAll(input io.Reader) error {
	contents, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	if err := ValidateCharacterClasses(bytes.NewReader(contents)); err != nil {
		return err
	}
	if err := ValidateCodePoints(bytes.NewReader(contents)); err != nil {
		return err
	}

	return nil
}

func ValidateCharacterClasses(input io.Reader) error {
	scanner := bufio.NewScanner(input)
	scanner.Split(scanCharacterClasses)
	for scanner.Scan() {
		err := validateCharacterClass(scanner.Text())
		if err != nil {
			return err
		}

	}
	return scanner.Err()
}

func ValidateCodePoints(input io.Reader) error {
	scanner := bufio.NewScanner(input)
	scanner.Split(scanUnicodeHexEscapeCodePoints)
	for scanner.Scan() {
		err := validateHexCodePoint(scanner.Text())
		if err != nil {
			return err
		}

	}
	return scanner.Err()
}

func validateHexCodePoint(codepoint string) error {
	maxCodePoint := uint64(255)
	parsedCodePoint, err := strconv.ParseUint(codepoint, 16, 32)
	if err != nil {
		return err
	}
	if parsedCodePoint <= maxCodePoint {
		return nil
	}

	return fmt.Errorf("unicode hex escape codepoint too big: %d > %d", parsedCodePoint, maxCodePoint)
}

func validateCharacterClass(innerTokens string) error {
	scanner := bufio.NewScanner(strings.NewReader(innerTokens))
	scanner.Split(bufio.ScanRunes)
	for scanner.Scan() {
		r := scanner.Bytes()
		if len(r) > 1 {
			return fmt.Errorf("found multi-byte character in character class: %s", scanner.Text())
		}
	}

	return nil
}

func scanUnicodeHexEscapeCodePoints(data []byte, atEOF bool) (advance int, token []byte, err error) {
	start := 0
	length := len(data)
	for ; start < length; start += 1 {
		if data[start] == backSlash && start+2 < length {
			if data[start+1] == backSlash {
				// escaped backslash
				start += 1
			} else if bytes.Equal(data[start:start+3], unicodeHexEscapePrefix) {
				// found start sequence
				start += 3
				break
			}
		}
	}
	if atEOF && start >= length {
		// nothing found; done
		return 0, nil, bufio.ErrFinalToken
	}

	for i := start; i < length; i += 1 {
		if data[i] == closingBrace {
			// found codepoint; return it
			return i + 1, data[start:i], nil
		}
	}

	// closing brace not found; request more data
	return start, nil, nil
}

func scanCharacterClasses(data []byte, atEOF bool) (advance int, token []byte, err error) {
	start := 0
	length := len(data)
	for ; start < length; start += 1 {
		if data[start] == backSlash && start+1 < length {
			switch data[start+1] {
			case backSlash:
				// escaped backslash; continue
				start += 1
			case openingBracket:
				// escaped opening bracket; continue
				start += 1
			}
		} else if data[start] == openingBracket {
			// found start sequence
			start += 1
			break
		}
	}
	if atEOF && start >= length {
		// nothing found; done
		return 0, nil, bufio.ErrFinalToken
	}

	for i := start; i < length; i += 1 {
		if data[start] == backSlash && start+1 < length {
			switch data[start+1] {
			case backSlash:
				// escaped backslash; continue
				i += 1
			case closingBracket:
				// escaped closing bracket; continue
				i += 1
			}
		} else if data[i] == closingBracket {
			// found character class; return it
			return i + 1, data[start:i], nil
		}
	}

	// closing bracket not found; request more data
	return start, nil, nil
}
