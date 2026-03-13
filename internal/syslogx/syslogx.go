package syslogx

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
)

type LoggerSet struct {
	Ops     *log.Logger
	Error   *log.Logger
	Access  *log.Logger
	closers []io.Closer
}

func New(component string, includeAccess bool) (*LoggerSet, error) {
	return newWithMirror(component, includeAccess, false)
}

// NewForCommand creates loggers for command-style execution and mirrors log
// messages to stdout when not running under systemd.
func NewForCommand(component string, includeAccess bool) (*LoggerSet, error) {
	return newWithMirror(component, includeAccess, !runningUnderSystemd())
}

func newWithMirror(component string, includeAccess, mirrorStdout bool) (*LoggerSet, error) {
	opsLogger, opsCloser, err := newLogger(component+"-ops", syslog.LOG_INFO, mirrorStdout)
	if err != nil {
		return nil, err
	}
	errLogger, errCloser, err := newLogger(component+"-error", syslog.LOG_ERR, mirrorStdout)
	if err != nil {
		_ = opsCloser.Close()
		return nil, err
	}

	ls := &LoggerSet{
		Ops:     opsLogger,
		Error:   errLogger,
		closers: []io.Closer{opsCloser, errCloser},
	}

	if includeAccess {
		accessLogger, accessCloser, accessErr := newLogger(component+"-access", syslog.LOG_INFO, mirrorStdout)
		if accessErr != nil {
			_ = ls.Close()
			return nil, accessErr
		}
		ls.Access = accessLogger
		ls.closers = append(ls.closers, accessCloser)
	}

	return ls, nil
}

func (l *LoggerSet) Close() error {
	var firstErr error
	for _, c := range l.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func newLogger(tag string, severity syslog.Priority, mirrorStdout bool) (*log.Logger, io.Closer, error) {
	writer, err := dialSyslogWriter(syslog.LOG_DAEMON|severity, tag)
	if err != nil {
		return nil, nil, err
	}
	loggerWriter := io.Writer(writer)
	if mirrorStdout {
		loggerWriter = io.MultiWriter(writer, os.Stdout)
	}
	return log.New(loggerWriter, "", 0), writer, nil
}

func runningUnderSystemd() bool {
	if os.Getenv("INVOCATION_ID") != "" {
		return true
	}
	if os.Getenv("JOURNAL_STREAM") != "" {
		return true
	}
	if os.Getenv("NOTIFY_SOCKET") != "" {
		return true
	}
	if os.Getenv("LISTEN_PID") != "" {
		return true
	}
	return false
}

func dialSyslogWriter(priority syslog.Priority, tag string) (*syslog.Writer, error) {
	for _, addr := range []string{"/run/httpsd/dev/log", "/dev/log"} {
		writer, err := syslog.Dial("unixgram", addr, priority, tag)
		if err == nil {
			return writer, nil
		}
	}
	return nil, fmt.Errorf("connect to syslog socket failed for tag %s", tag)
}
