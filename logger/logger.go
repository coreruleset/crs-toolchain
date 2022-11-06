// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const DefaultLogLevel zerolog.Level = zerolog.InfoLevel

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "03:04:05"}).With().Caller().Logger()
	zerolog.SetGlobalLevel(DefaultLogLevel)
}
