package helpers

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

// LogEntry is a single emitted log line
type LogEntry struct {
	Time    time.Time
	Level   string
	Message string
}

// Logger provides aggregated logging
type Logger struct {
	out     io.Writer
	entries []LogEntry
}

// timeFormat is RFC3339 with milliseconds, so lines correlate against cluster logs
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

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

func (l *Logger) Entries() []LogEntry {
	return l.entries
}

// Writer exposes the log's destination for callers that print raw blocks outside Log/Warn/Error
func (l *Logger) Writer() io.Writer {
	return l.writer()
}

func (l *Logger) NewLine() {
	fmt.Fprintf(l.writer(), "\n")
}

func (l *Logger) write(level, format string, args ...interface{}) {
	entry := LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: fmt.Sprintf(format, args...),
	}
	l.entries = append(l.entries, entry)

	fmt.Fprintf(l.writer(), "%s %s ▶ %s\n",
		entry.Time.Format(timeFormat), entry.Level, entry.Message)
}

// Log writes to the log at INFO level
func (l *Logger) Log(format string, args ...interface{}) {
	l.write("INFO", format, args...)
}

// Warn writes to the log at WARN level
func (l *Logger) Warn(format string, args ...interface{}) {
	l.write("WARN", format, args...)
}

// Error writes to the log at ERROR level
func (l *Logger) Error(format string, args ...interface{}) {
	l.write("ERRO", format, args...)
}

func (l Logger) linesAt(level string) []string {
	var out []string
	for _, entry := range l.entries {
		if entry.Level == level {
			out = append(out, entry.Message)
		}
	}

	return out
}

// PrintSummary prints a summary of the emitted logs
func (l Logger) PrintSummary() {
	out := l.writer()

	fmt.Fprintf(out, "Summary:\n")

	warns := l.linesAt("WARN")
	errors := l.linesAt("ERRO")

	for _, line := range warns {
		fmt.Fprintf(out, "%s %s\n", color.YellowString("[WARN]"), line)
	}
	for _, line := range errors {
		fmt.Fprintf(out, "%s %s\n", color.RedString("[ERRO]"), line)
	}

	fmt.Fprintf(out, "\n%s\n", closingLine(len(warns), len(errors)))
}

func closingLine(warns, errors int) string {
	if warns == 0 && errors == 0 {
		return "Nothing of importance to note!  Nice job!"
	}

	var parts []string
	if warns > 0 {
		parts = append(parts, pluralCount(warns, "warning"))
	}
	if errors > 0 {
		parts = append(parts, pluralCount(errors, "error"))
	}

	line := fmt.Sprintf("Found %s, see listing above.", strings.Join(parts, ", "))
	if errors > 0 {
		return color.RedString(line)
	}
	return color.YellowString(line)
}

func pluralCount(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
