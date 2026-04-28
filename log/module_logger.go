package log

import (
	"fmt"
)

type ModuleLogger struct {
	reqId  int32
	name   string
	logger Logger
}

func NewModuleLogger(reqId int32, name string, logger Logger) *ModuleLogger {
	return &ModuleLogger{reqId, name, logger}
}

func (ml *ModuleLogger) Tracef(format string, args ...any) {
	ml.logger.Tracef(ml.getFormat(format), args...)
}

func (ml *ModuleLogger) Debugf(format string, args ...any) {
	ml.logger.Debugf(ml.getFormat(format), args...)
}

func (ml *ModuleLogger) Infof(format string, args ...any) {
	ml.logger.Infof(ml.getFormat(format), args...)
}

func (ml *ModuleLogger) Errorf(format string, args ...any) {
	ml.logger.Errorf(ml.getFormat(format), args...)
}

func (ml *ModuleLogger) Fatalf(format string, args ...any) {
	ml.logger.Fatalf(ml.getFormat(format), args...)
}

func (ml *ModuleLogger) getFormat(format string) string {
	return fmt.Sprintf("(%d) %s: %s", ml.reqId, ml.name, format)
}
