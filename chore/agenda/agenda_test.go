package agenda

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type choreAgendaTestSuite struct {
	suite.Suite
}

func TestRunChoreAgendaTestSuite(t *testing.T) {
	suite.Run(t, new(choreAgendaTestSuite))
}

func (s *choreAgendaTestSuite) TestComputeNextDate_OnSameDay() {
	date, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	next := computeNextDate(date)
	s.Equal(date, next)
}

func (s *choreAgendaTestSuite) TestComputeNextDate_OnDayBefore() {
	date, err := time.Parse(time.DateOnly, "2026-05-03")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	next := computeNextDate(date)
	s.Equal(expectedDate, next)
}

func (s *choreAgendaTestSuite) TestComputeNextDate_OnMondayBefore() {
	date, err := time.Parse(time.DateOnly, "2026-04-20")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	next := computeNextDate(date)
	s.Equal(expectedDate, next)
}

func (s *choreAgendaTestSuite) TestComputeNextDate_EightDaysBefore() {
	date, err := time.Parse(time.DateOnly, "2026-04-19")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	next := computeNextDate(date)
	s.Equal(expectedDate, next)
}

func (s *choreAgendaTestSuite) TestComputePreviousDate_OnSameDay() {
	date, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-04-06")
	s.Require().NoError(err)

	previous := computePreviousDate(date)
	s.Equal(expectedDate, previous)
}

func (s *choreAgendaTestSuite) TestComputePreviousDate_OnDayAfter() {
	date, err := time.Parse(time.DateOnly, "2026-05-05")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	previous := computePreviousDate(date)
	s.Equal(expectedDate, previous)
}

func (s *choreAgendaTestSuite) TestComputePreviousDate_OnMondayAfter() {
	date, err := time.Parse(time.DateOnly, "2026-05-11")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	previous := computePreviousDate(date)
	s.Equal(expectedDate, previous)
}

func (s *choreAgendaTestSuite) TestComputePreviousDate_EightDaysAfter() {
	date, err := time.Parse(time.DateOnly, "2026-05-12")
	s.Require().NoError(err)
	expectedDate, err := time.Parse(time.DateOnly, "2026-05-04")
	s.Require().NoError(err)

	previous := computePreviousDate(date)
	s.Equal(expectedDate, previous)
}
