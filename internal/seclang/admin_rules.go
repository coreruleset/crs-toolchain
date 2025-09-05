// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"strconv"
)

// isAdministrativeRule checks if a rule ID ends in the range 1-8
// This is a simplified version that focuses on the specific requirement
// to skip rules with IDs ending in 1-8
func isAdministrativeRule(id int) bool {
	strId := strconv.Itoa(id)
	lastDigit := strId[len(strId)-1:]
	return lastDigit >= "1" && lastDigit <= "8"
}
