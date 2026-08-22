package helpers

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
)

// Logger provides aggregated logging
type Logger struct {
	out    io.Writer
	warns  []string
	errors []string
}

func timeLogStr() string {
	t := time.Now()
	return fmt.Sprintf("%02d:%02d:%02d.%03d",
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/int(time.Millisecond))
}

// SetOutput redirects the log, which writes to stdout by default
func (l *Logger) SetOutput(w io.Writer) {
	l.out = w
}

func (l *Logger) writer() io.Writer {
	if l.out == nil {
		return os.Stdout
	}

	return l.out
}

// NewLine adds a new line to the log
func (l *Logger) NewLine() {
	fmt.Fprintf(l.writer(), "\n")
}

// Log writes to the log at INFO level
func (l *Logger) Log(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.writer(), "%s INFO ▶ %s\n", timeLogStr(), line)
}

// Warn writes to the log at WARN level
func (l *Logger) Warn(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.writer(), "%s WARN ▶ %s\n", timeLogStr(), line)
	l.warns = append(l.warns, line)
}

// Error writes to the log at ERROR level
func (l *Logger) Error(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.writer(), "%s ERRO ▶ %s\n", timeLogStr(), line)
	l.errors = append(l.errors, line)
}

// PrintSummary prints a summary of the emitted logs
func (l Logger) PrintSummary() {
	out := l.writer()

	fmt.Fprintf(out, "Summary:\n")

	for _, line := range l.warns {
		fmt.Fprintf(out, "%s %s\n", color.YellowString("[WARN]"), line)
	}
	for _, line := range l.errors {
		fmt.Fprintf(out, "%s %s\n", color.RedString("[ERRO]"), line)
	}

	fmt.Fprintf(out, "\n")
	if len(l.warns) > 0 || len(l.errors) > 0 {
		fmt.Fprintf(out, "Found multiple issues, see listing above.\n")
	} else {
		fmt.Fprintf(out, "Nothing of importance to note!  Nice job!\n")
	}
}
