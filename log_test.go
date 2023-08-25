package kpx

import (
	"github.com/ccding/go-logging/logging"
	"os"
	"testing"
)

func TestLogging(t *testing.T) {
	logFormat := "%s\nmessage"
	timeFormat := "2006-01-02 15:04:05"
	logger, _ := logging.CustomizedLogger("main", logging.WARNING, logFormat, timeFormat, os.Stdout, false, logging.DefaultQueueSize, logging.DefaultRequestSize, logging.DefaultBufferSize, logging.DefaultTimeInterval)
	defer logger.Destroy()
	logger.Error("this is a test from error")
	logger.Flush()
}
