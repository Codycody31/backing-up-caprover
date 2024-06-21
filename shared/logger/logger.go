package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Logger struct for custom logging
type Logger struct {
	mu        sync.Mutex
	file      *os.File
	logger    *log.Logger
	logFile   string
	logFolder string
	maxSize   int64
}

// LogLevel type to define log levels
type LogLevel int

const (
	INFO LogLevel = iota
	WARN
	ERROR
	SUCCESS
	WELCOME
)

// LogLevelString map to convert log levels to strings
var LogLevelString = map[LogLevel]string{
	INFO:    "INFO",
	WARN:    "WARN",
	ERROR:   "ERROR",
	SUCCESS: "SUCCESS",
	WELCOME: "WELCOME",
}

// String method to convert log level to string
func (l LogLevel) String() string {
	return LogLevelString[l]
}

// LogEntry struct to define a log entry
type LogEntry struct {
	Level   LogLevel
	Message string
	Server  string
	Task    string
}

// LogOption function type for functional options
type LogOption func(*LogEntry)

// NewLogger initializes a new logger instance
func NewLogger(logFile string, maxSizeMB int) (*Logger, error) {
	logger := &Logger{
		logFile: logFile,
		// strip the file name from the logFile path
		logFolder: strings.TrimSuffix(logFile, filepath.Base(logFile)),
		maxSize:   int64(maxSizeMB * 1024 * 1024), // Convert MB to bytes
	}

	if err := os.MkdirAll(logger.logFolder, 0755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(logger.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	logger.file = file
	logger.logger = log.New(file, "", log.LstdFlags)

	return logger, nil
}

// rotateLogFile rotates the log file if it exceeds the maxSize
func (l *Logger) rotateLogFile() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, err := os.Stat(l.logFile)
	if err != nil {
		return err
	}

	if info.Size() < l.maxSize {
		return nil
	}

	newName := fmt.Sprintf("%s.%s", l.logFile, time.Now().Format("2006-01-02-15-04-05"))
	if err := os.Rename(l.logFile, newName); err != nil {
		return err
	}

	file, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	l.file.Close()
	l.file = file
	l.logger.SetOutput(file)
	return nil
}

// log formats and logs a message with the given log entry
func (l *Logger) log(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// TODO: This errors out, and doesn't work/hangs
	// if err := l.rotateLogFile(); err != nil {
	// 	log.Printf("Failed to rotate log file: %v", err)
	// }

	message := fmt.Sprintf("[%s] [%s] %s", time.Now().Format(time.RFC3339), strings.ToUpper(entry.Level.String()), entry.Message)

	if entry.Server != "" {
		message = fmt.Sprintf("%s - Server: %s", message, entry.Server)
	}
	if entry.Task != "" {
		message = fmt.Sprintf("%s - Task: %s", message, entry.Task)
	}

	switch entry.Level {
	case INFO:
		message = fmt.Sprintf("\033[34m%s\033[0m", message)
	case WARN:
		message = fmt.Sprintf("\033[33m%s\033[0m", message)
	case ERROR:
		message = fmt.Sprintf("\033[31m%s\033[0m", message)
	case SUCCESS:
		message = fmt.Sprintf("\033[32m%s\033[0m", message)
	case WELCOME:
		message = fmt.Sprintf("\033[35m%s\033[0m", message)
	}

	l.logger.Println(message)
	fmt.Println(message)
}

// Log creates a log entry with the provided options
func (l *Logger) Log(level LogLevel, message string, options ...LogOption) {
	entry := LogEntry{
		Level:   level,
		Message: message,
	}

	for _, option := range options {
		option(&entry)
	}

	l.log(entry)
}

// WithServer adds a server to the log entry
func WithServer(server string) LogOption {
	return func(entry *LogEntry) {
		entry.Server = server
	}
}

// WithTask adds a task to the log entry
func WithTask(task string) LogOption {
	return func(entry *LogEntry) {
		entry.Task = task
	}
}
