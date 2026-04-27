package log

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ccding/go-logging/logging"
)

const (
	logFormat  = "%s %s\n time,message"
	timeFormat = "2006/01/02 15:04:05.999"
)

type defaultLogger struct {
	mode   LogMode
	level  LogLevel
	logger *logging.Logger
	mutex  sync.Mutex
}

func NewDefaultLogger() Logger {
	return &defaultLogger{
		mode:   LogModeSync,
		level:  LogLevelInfo,
		logger: nil,
	}
}

func (l *defaultLogger) SetMode(mode LogMode) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.mode == mode {
		return
	}
	l.mode = mode
	switch mode {
	case LogModeSync:
		if l.logger != nil {
			l.logger.Flush()
		}
	case LogModeAsync:
		if l.logger == nil {
			l.logger = initAsyncLogger()
			if l.logger == nil {
				l.mode = LogModeSync
			}
		}
	case LogModeNone:
	}
}

func initAsyncLogger() *logging.Logger {
	logger, err := logging.CustomizedLogger("main", logging.NOTSET, logFormat, timeFormat, os.Stdout, false, logging.DefaultQueueSize, logging.DefaultRequestSize, logging.DefaultBufferSize, logging.DefaultTimeInterval)
	if err != nil {
		fmt.Printf("Error: unable to create logger: %v", err)
		return nil
	}
	return logger
}

func (l *defaultLogger) SetLogLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

func (l *defaultLogger) Destroy() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.logger != nil {
		l.logger.Destroy()
		l.logger = nil
	}
	if l.mode == LogModeAsync {
		l.mode = LogModeSync
	}
}

func (l *defaultLogger) Tracef(format string, args ...any) {
	l.printf(LogLevelTrace, format, args...)
}

func (l *defaultLogger) Debugf(format string, args ...any) {
	l.printf(LogLevelDebug, format, args...)
}

func (l *defaultLogger) Infof(format string, args ...any) {
	l.printf(LogLevelInfo, format, args...)
}

func (l *defaultLogger) Errorf(format string, args ...any) {
	l.printf(LogLevelError, format, args...)
}

func (l *defaultLogger) printf(level LogLevel, format string, args ...any) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if level < l.level {
		return
	}
	switch l.mode {
	case LogModeSync:
		format = fmt.Sprintf("%s %s %s", time.Now().Format(timeFormat), logShortName[level], format)
		fmt.Printf(format, args...)
	case LogModeAsync:
		if l.logger != nil {
			format = fmt.Sprintf("%s %s", logShortName[level], format)
			l.logger.Infof(format, args...)
		}
	case LogModeNone:
	}
}
