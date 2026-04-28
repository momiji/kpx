package log

type LogMode int

const (
	LogModeSync LogMode = iota
	LogModeAsync
	LogModeNone
)

type LogLevel int

const (
	LogLevelTrace LogLevel = iota
	LogLevelDebug
	LogLevelInfo
	LogLevelError
)

var logShortName = map[LogLevel]string{
	LogLevelTrace: "T",
	LogLevelDebug: "D",
	LogLevelInfo:  "I",
	LogLevelError: "E",
}

type Logger interface {
	// GetMode returns the current logging mode.
	GetMode() LogMode
	// SetMode sets the logging mode. If the mode is LogModeAsync, it initializes the asynchronous logger.
	SetMode(mode LogMode)
	// Destroy flushes any buffered log messages and releases resources used by the logger. After calling Destroy, the logger should not be used.
	Destroy()
	// SetLogLevel sets the logging level. Messages below this level will not be logged.
	SetLogLevel(level LogLevel)
	// Tracef logs a formatted message at the Trace level.
	Tracef(format string, args ...any)
	// Debugf logs a formatted message at the Debug level.
	Debugf(format string, args ...any)
	// Infof logs a formatted message at the Info level.
	Infof(format string, args ...any)
	// Errorf logs a formatted message at the Error level.
	Errorf(format string, args ...any)
	// Fatalf logs a formatted message at the Error level and then terminates the program.
	Fatalf(format string, args ...any)
}
