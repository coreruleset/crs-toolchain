// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// AdministrativeRulesTestSuite contains tests for administrative rule detection
type AdministrativeRulesTestSuite struct {
	suite.Suite
}

// TestAdministrativeRulesTestSuite runs the test suite
func TestAdministrativeRulesTestSuite(t *testing.T) {
	suite.Run(t, new(AdministrativeRulesTestSuite))
}

// TestIsAdministrativeRule tests the isAdministrativeRule function
func (suite *AdministrativeRulesTestSuite) TestIsAdministrativeRule() {
	tests := []struct {
		name     string
		id       int
		expected bool
	}{
		{
			name:     "Rule ending in 1 should be administrative",
			id:       932101,
			expected: true,
		},
		{
			name:     "Rule ending in 2 should be administrative",
			id:       920012,
			expected: true,
		},
		{
			name:     "Rule ending in 3 should be administrative",
			id:       941013,
			expected: true,
		},
		{
			name:     "Rule ending in 4 should be administrative",
			id:       933014,
			expected: true,
		},
		{
			name:     "Rule ending in 5 should be administrative",
			id:       920015,
			expected: true,
		},
		{
			name:     "Rule ending in 6 should be administrative",
			id:       932016,
			expected: true,
		},
		{
			name:     "Rule ending in 7 should be administrative",
			id:       933017,
			expected: true,
		},
		{
			name:     "Rule ending in 8 should be administrative",
			id:       920018,
			expected: true,
		},
		{
			name:     "Rule ending in 0 should not be administrative",
			id:       932100,
			expected: false,
		},
		{
			name:     "Rule ending in 9 should not be administrative",
			id:       920019,
			expected: false,
		},
		{
			name:     "Single digit rule ending in 1 should be administrative",
			id:       1,
			expected: true,
		},
		{
			name:     "Single digit rule ending in 5 should be administrative",
			id:       5,
			expected: true,
		},
		{
			name:     "Single digit rule ending in 9 should not be administrative",
			id:       9,
			expected: false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			result := isAdministrativeRule(tt.id)
			assert.Equal(suite.T(), tt.expected, result, "isAdministrativeRule(%d) should return %v", tt.id, tt.expected)
		})
	}
}
