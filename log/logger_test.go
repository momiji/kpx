package log

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// captureStdout redirects os.Stdout during f() and returns what was written.
func captureStdout(f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	orig := os.Stdout
	os.Stdout = w

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(&buf, r)
	}()

	f()

	w.Close()
	os.Stdout = orig
	wg.Wait()
	r.Close()
	return buf.String()
}

func TestNewDefaultLogger_ImplementsInterface(t *testing.T) {
	var _ Logger = NewDefaultLogger()
}

func TestNewDefaultLogger_Defaults(t *testing.T) {
	l := NewDefaultLogger().(*defaultLogger)
	if l.mode != LogModeSync {
		t.Errorf("expected default mode LogModeSync, got %v", l.mode)
	}
	if l.level != LogLevelInfo {
		t.Errorf("expected default level LogLevelInfo, got %v", l.level)
	}
	if l.logger != nil {
		t.Error("expected nil async logger on a fresh defaultLogger")
	}
}

func TestSetLogLevel_TraceLevel(t *testing.T) {
	l := NewDefaultLogger()
	l.SetLogLevel(LogLevelTrace)

	out := captureStdout(func() {
		l.Tracef("trace should appear\n")
		l.Debugf("debug should appear\n")
		l.Infof("info should appear\n")
		l.Errorf("error should appear\n")
	})
	if !strings.Contains(out, "trace should appear") {
		t.Error("Tracef output did not appear when level is Trace")
	}
	if !strings.Contains(out, "debug should appear") {
		t.Error("Debugf output did not appear when level is Trace")
	}
	if !strings.Contains(out, "info should appear") {
		t.Error("Infof output did not appear when level is Trace")
	}
	if !strings.Contains(out, "error should appear") {
		t.Error("Errorf output did not appear when level is Trace")
	}
}

func TestSetLogLevel_DebugLevel(t *testing.T) {
	l := NewDefaultLogger()
	l.SetLogLevel(LogLevelDebug)

	out := captureStdout(func() {
		l.Tracef("trace should not appear\n")
		l.Debugf("debug should appear\n")
		l.Infof("info should appear\n")
		l.Errorf("error should appear\n")
	})
	if strings.Contains(out, "should not appear") {
		t.Error("Tracef output leaked through when level is Debug")
	}
	if !strings.Contains(out, "debug should appear") {
		t.Error("Debugf output did not appear when level is Debug")
	}
	if !strings.Contains(out, "info should appear") {
		t.Error("Infof output did not appear when level is Debug")
	}
	if !strings.Contains(out, "error should appear") {
		t.Error("Errorf output did not appear when level is Debug")
	}
}

func TestSetLogLevel_InfoLevel(t *testing.T) {
	l := NewDefaultLogger()
	l.SetLogLevel(LogLevelInfo)

	out := captureStdout(func() {
		l.Tracef("trace should not appear\n")
		l.Debugf("debug should not appear\n")
		l.Infof("info should appear\n")
		l.Errorf("error should appear\n")
	})
	if strings.Contains(out, "should not appear") {
		t.Error("Tracef or Debugf output leaked through when level is Info")
	}
	if !strings.Contains(out, "info should appear") {
		t.Error("Infof output did not appear when level is Info")
	}
	if !strings.Contains(out, "error should appear") {
		t.Error("Errorf output did not appear when level is Info")
	}
}

func TestSetLogLevel_ErrorLevel(t *testing.T) {
	l := NewDefaultLogger()
	l.SetLogLevel(LogLevelError)

	out := captureStdout(func() {
		l.Tracef("trace should not appear\n")
		l.Debugf("debug should not appear\n")
		l.Infof("info should not appear\n")
		l.Errorf("error should appear\n")
	})
	if strings.Contains(out, "should not appear") {
		t.Error("Tracef, Debugf, or Infof output leaked through when level is Error")
	}
	if !strings.Contains(out, "error should appear") {
		t.Error("Errorf output did not appear when level is Error")
	}
}

func TestSetMode_None_SuppressesOutput(t *testing.T) {
	l := NewDefaultLogger()
	l.SetMode(LogModeNone)

	out := captureStdout(func() {
		l.Infof("suppressed\n")
		l.Debugf("also suppressed\n")
		l.Errorf("still suppressed\n")
	})
	if out != "" {
		t.Errorf("expected no output in LogModeNone, got %q", out)
	}
}

func TestSetMode_Async_NoPanic(t *testing.T) {
	l := NewDefaultLogger()
	l.SetMode(LogModeAsync)
	defer l.Destroy()

	// Just ensure no panic; async output is buffered and flushed on Destroy.
	l.Infof("async info\n")
	l.Debugf("async debug\n")
}

func TestSetMode_Transitions(t *testing.T) {
	l := NewDefaultLogger()
	defer l.Destroy()

	transitions := []LogMode{
		LogModeSync,
		LogModeAsync,
		LogModeSync,
		LogModeNone,
		LogModeSync,
		LogModeAsync,
		LogModeNone,
	}
	for _, m := range transitions {
		l.SetMode(m)
		l.Infof("transition test\n")
	}
}

func TestSetMode_SameMode_NoOp(t *testing.T) {
	l := NewDefaultLogger()
	// Setting the same mode twice should not panic or create an async logger.
	l.SetMode(LogModeSync)
	l.SetMode(LogModeSync)

	inner := l.(*defaultLogger)
	if inner.logger != nil {
		t.Error("unexpected async logger created on repeated sync mode set")
	}
}

func TestDestroy_FreshLogger(t *testing.T) {
	l := NewDefaultLogger()
	// Destroy before async mode is ever set must not panic.
	l.Destroy()
}

func TestDestroy_Idempotent(t *testing.T) {
	l := NewDefaultLogger()
	l.SetMode(LogModeAsync)
	l.Infof("before destroy\n")
	l.Destroy()
	l.Destroy() // second call must not panic
}

func TestAllMethods_Smoke(t *testing.T) {
	modes := []LogMode{LogModeSync, LogModeNone}
	levels := []LogLevel{LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelError}

	for _, mode := range modes {
		for _, lvl := range levels {
			l := NewDefaultLogger()
			l.SetMode(mode)
			l.SetLogLevel(lvl)

			captureStdout(func() {
				l.Tracef("trace %s\n", "msg")
				l.Debugf("debug %s\n", "msg")
				l.Infof("info %s\n", "msg")
				l.Errorf("error %s\n", "msg")
			})

			l.Destroy()
		}
	}
}

func TestAllMethods_AsyncSmoke(t *testing.T) {
	l := NewDefaultLogger()
	l.SetMode(LogModeAsync)
	l.SetLogLevel(LogLevelTrace)

	l.Tracef("async trace %d\n", 0)
	l.Debugf("async debug %d\n", 1)
	l.Infof("async info %d\n", 2)
	l.Errorf("async error %d\n", 3)

	l.Destroy()
}
