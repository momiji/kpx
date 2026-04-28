package log

import (
	"fmt"
)

type RequestLogger struct {
	reqId  int32
	logger Logger
}

func NewRequestLogger(reqId int32, logger Logger) *RequestLogger {
	return &RequestLogger{reqId, logger}
}

func (rl *RequestLogger) Tracef(format string, args ...any) {
	rl.logger.Tracef(rl.getFormat(format), args...)
}

func (rl *RequestLogger) Debugf(format string, args ...any) {
	rl.logger.Debugf(rl.getFormat(format), args...)
}

func (rl *RequestLogger) Infof(format string, args ...any) {
	rl.logger.Infof(rl.getFormat(format), args...)
}

func (rl *RequestLogger) Errorf(format string, args ...any) {
	rl.logger.Errorf(rl.getFormat(format), args...)
}

func (rl *RequestLogger) Fatalf(format string, args ...any) {
	rl.logger.Fatalf(rl.getFormat(format), args...)
}

func (rl *RequestLogger) getFormat(format string) string {
	return fmt.Sprintf("(%d) %s", rl.reqId, format)
}
