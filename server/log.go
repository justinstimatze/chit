package server

import (
	"log"
	"os"
)

// Logger is the minimal logging surface the merchant side uses. It mirrors the
// TS SDK's Logger (debug/info/warn/error).
//
// Security note: chit never passes a connection string, bearer token, opaque
// HMAC key, or payment credential to any Logger method. Implementations may send
// log output anywhere; the contract is that nothing handed to a Logger is a
// secret, so a custom Logger cannot accidentally exfiltrate one.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// nopLogger discards everything. It is the default so that a merchant which
// wires in no Logger never emits payment metadata to stderr by surprise.
type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// StdLogger writes warn- and error-level lines to the standard library logger
// (stderr by default) and drops debug/info. It is a convenience for merchants
// that want operational visibility without a logging dependency.
type StdLogger struct{ l *log.Logger }

// NewStdLogger returns a StdLogger writing to stderr.
func NewStdLogger() *StdLogger {
	return &StdLogger{l: log.New(os.Stderr, "atxp-server ", log.LstdFlags)}
}

func (s *StdLogger) Debugf(string, ...any)             {}
func (s *StdLogger) Infof(string, ...any)              {}
func (s *StdLogger) Warnf(format string, args ...any)  { s.l.Printf("WARN  "+format, args...) }
func (s *StdLogger) Errorf(format string, args ...any) { s.l.Printf("ERROR "+format, args...) }
