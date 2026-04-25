// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type loggerTestSuite struct {
	suite.Suite
	out    *bytes.Buffer
	logger zerolog.Logger
}

func TestRunLoggerTestSuite(t *testing.T) {
	suite.Run(t, new(loggerTestSuite))
}

var testJsonBase = []struct {
	name     string
	text     string
	logLevel zerolog.Level
	want     string
}{
	{
		name:     "JsonBaseOutput",
		text:     "hello",
		logLevel: zerolog.InfoLevel,
		want:     "message\":\"hello\"",
	},
}

var testConsoleBase = []struct {
	name     string
	text     string
	logLevel zerolog.Level
	want     string
}{
	{
		name:     "BaseConsoleOutput",
		text:     "hello",
		logLevel: zerolog.InfoLevel,
		want:     "INF hello component=parser-test",
	},
}

var testGithub = []struct {
	name     string
	text     string
	logLevel zerolog.Level
	want     string
}{
	{
		name:     "TestGithubInfoOutput",
		text:     "this is an info message",
		logLevel: zerolog.InfoLevel,
		want:     "::notice ::this is an info message",
	},
	{
		name:     "TestGithubWarningOutput",
		text:     "this is a warning message",
		logLevel: zerolog.WarnLevel,
		want:     "::warn ::this is a warning message",
	},
	{
		name:     "TestGithubTraceOutput",
		text:     "this is a trace message that will show as debug",
		logLevel: zerolog.TraceLevel,
		want:     "::debug ::this is a trace message that will show as debug",
	},
	{
		name:     "TestGithubDebugOutput",
		text:     "this is a debug message",
		logLevel: zerolog.DebugLevel,
		want:     "::debug ::this is a debug message",
	},
	{
		name:     "TestGithubErrorOutput",
		text:     "this is an error message",
		logLevel: zerolog.ErrorLevel,
		want:     "::error  ::this is an error message",
	},
	{
		name:     "TestGithubFatalOutput",
		text:     "this is a fatal message",
		logLevel: zerolog.FatalLevel,
		want:     "::error  ::this is a fatal message",
	},
	{
		name:     "TestGithubPanicOutput",
		text:     "this is a panic message",
		logLevel: zerolog.PanicLevel,
		want:     "::error  ::this is a panic message",
	},
}

func (s *loggerTestSuite) SetupTest() {
	// reset logger
	s.out = &bytes.Buffer{}
	s.logger = zerolog.New(s.out).With().Str("component", "parser-test").Logger()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
}

func (s *loggerTestSuite) TestJsonOutput() {
	for _, t := range testJsonBase {
		s.Run(t.name, func() {
			s.logger.WithLevel(t.logLevel).Msg(t.text)
			s.Contains(s.out.String(), t.want)
			s.out.Reset()
		})
	}
}

func (s *loggerTestSuite) TestConsoleOutput() {
	s.logger = s.logger.Output(zerolog.ConsoleWriter{Out: s.out, NoColor: true, TimeFormat: "03:04:05"})
	for _, t := range testConsoleBase {
		s.Run(t.name, func() {
			s.logger.WithLevel(t.logLevel).Msg(t.text)
			s.Contains(s.out.String(), t.want)
			s.out.Reset()
		})
	}
}

func (s *loggerTestSuite) TestSetGithubOutput() {
	logger := SetGithubOutput(s.out)
	for _, t := range testGithub {
		s.Run(t.name, func() {
			logger.WithLevel(t.logLevel).Msg(t.text)
			s.Contains(s.out.String(), t.want)
			s.out.Reset()
		})
	}
}
