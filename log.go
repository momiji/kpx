package kpx

import (
	"fmt"
	"github.com/ccding/go-logging/logging"
	"os"
	"strings"
	"time"
)

const (
	logFormat  = "%s %s\n time,message"
	timeFormat = "2006/01/02 15:04:05"
)

func logInit() {
	var err error
	logger, err = logging.CustomizedLogger("main", logging.NOTSET, logFormat, timeFormat, os.Stdout, false, logging.DefaultQueueSize, logging.DefaultRequestSize, logging.DefaultBufferSize, logging.DefaultTimeInterval)
	if err != nil {
		fmt.Printf("Error: unable to create logger: %v", err)
		os.Exit(1)
	}
}

func logDestroy() {
	logger.Destroy()
}

func logPrintf(format string, a ...any) {
	format = fmt.Sprintf("%s %s", time.Now().Format(timeFormat), format)
	fmt.Printf(format, a...)
}

func logHeader(format string, prefix string, header string) {
	lower := strings.ToLower(header)
	if strings.HasPrefix(lower, "proxy-authorization:") {
		l := len(header)
		if l-10 > 50 {
			l = 50
		} else {
			l = l - 10
			if l < 20 {
				l = 20
			}
		}
		header = header[:l] + "..."
	}
	logger.Infof(format, prefix, header)
}

type traceInfo struct {
	reqId int32
	name  string
}

func newTraceInfo(reqId int32, name string) *traceInfo {
	return &traceInfo{reqId, name}
}

func logTrace(ti *traceInfo, format string, args ...interface{}) {
	logger.Debugf(fmt.Sprintf("(%d) %s: %s", ti.reqId, ti.name, format), args...)
}
func logInfo(format string, args ...interface{}) {
	logger.Infof(format, args...)
}

func logError(format string, args ...interface{}) {
	logger.Errorf(format, args...)
}

func logFatal(format string, args ...interface{}) {
	logger.Fatalf(format, args...)
	logger.Destroy()
	os.Exit(1)
}
