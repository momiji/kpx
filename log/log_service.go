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
	SetMode(mode LogMode)
	Destroy()
	SetLogLevel(level LogLevel)
	Tracef(format string, args ...any)
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}
