// internal/logger/logger.go

package logger

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	ERROR Level = iota
	WARNING
	SUCCESS
	INFO
	DEBUG
)

type Logger struct {
	verbosity int
	debug     bool
	mu        sync.Mutex
	writer    io.Writer
	colors    map[Level]string
	reset     string
}

func New(verbosity int, debug bool) (*Logger, error) {
	return &Logger{
		verbosity: verbosity,
		debug:     debug,
		writer:    os.Stdout,
		colors: map[Level]string{
			ERROR:   "\033[31m", // Red
			WARNING: "\033[33m", // Yellow
			SUCCESS: "\033[32m", // Green
			INFO:    "\033[34m", // Blue
			DEBUG:   "\033[35m", // Purple
		},
		reset: "\033[0m",
	}, nil
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = w
}

func (l *Logger) log(level Level, prefix, msg string, verbosity int) {
	if l.verbosity < verbosity {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	color := l.colors[level]

	fmt.Fprintf(l.writer, "%s %s[%s]%s %s\n",
		timestamp,
		color,
		prefix,
		l.reset,
		msg,
	)

	if l.debug && level == ERROR {
		// Print stack trace in debug mode
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		stackTrace := strings.ReplaceAll(string(buf[:n]), "\n", "\n\t")
		fmt.Fprintf(l.writer, "%s %s[DEBUG]%s Stack Trace:\n\t%s\n",
			timestamp,
			l.colors[DEBUG],
			l.reset,
			stackTrace,
		)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, "X", fmt.Sprintf(format, args...), 0)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, "-", fmt.Sprintf(format, args...), 0)
}

func (l *Logger) Success(format string, args ...interface{}) {
	l.log(SUCCESS, "+", fmt.Sprintf(format, args...), 0)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, "*", fmt.Sprintf(format, args...), 0)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		l.log(DEBUG, "D", fmt.Sprintf(format, args...), 0)
	}
}

func (l *Logger) Verbose(level int, format string, args ...interface{}) {
	if l.verbosity >= level {
		l.log(INFO, fmt.Sprintf("V%d", level), fmt.Sprintf(format, args...), level)
	}
}

func (l *Logger) Plain(format string, args ...interface{}) {
	if l.verbosity > 0 {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Fprintf(l.writer, format+"\n", args...)
	}
}
