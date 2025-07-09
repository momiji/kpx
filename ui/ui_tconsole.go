package ui

import (
	"github.com/momiji/kpx/term"
	"os"
)

var consoleClosed = NewManualResetEvent(true)
var closeConsole = NewManualResetEvent(false)
var consoleInited = false
var consoleChan = make(chan byte)

func consoleRun() {
	if !consoleInited {
		go readConsole(consoleChan)
		consoleInited = true
	}
	consoleClosed.Reset()
	defer consoleClosed.Signal()
	closeConsole.Reset()
	// backup term state and restore it on return
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	// console loop
	loop := true
	cc := closeConsole.Channel()
	for loop {
		select {
		case <-cc:
			closeConsole.Reset()
			loop = false
		case b := <-consoleChan:
			IfConsole(func() {
				switch b {
				case 'q', 'Q', '\x03':
					close(quitUI)
					loop = false
				case ' ', '\x1b', '\x09':
					loop = false
				case '\x0a', '\x0d':
					PrintUI("")
				}
			})
		}
	}
}

func consoleClose() {
	closeConsole.Signal()
}

func readConsole(c chan byte) {
	b := make([]byte, 10)
	for {
		n, err := os.Stdin.Read(b)
		if err != nil {
			continue
		}
		if n > 0 {
			IfAppConsole(func(console bool) {
				if console {
					c <- b[0]
				} else {
					appKeyNoLock(b[0])
				}
			})
		}
	}
}
