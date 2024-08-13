package app

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

// Initialize the logger with specific settings.
func InitLogger(logLevel string) {
	log = logrus.New()

	// Set the log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", logLevel)
	}
	log.SetLevel(level)

	// Set output to stdout
	log.SetOutput(os.Stdout)

	// Set the formatter (you can customize the format)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})

	// Example of adding a hook (optional)
	// log.AddHook(someHook)
}

// GetLogger returns the initialized logger instance
func GetLogger() *logrus.Logger {
	if log == nil {
		InitLogger("info") // default level
	}
	return log
}
