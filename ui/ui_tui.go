package ui

import (
	"github.com/dustin/go-humanize"
	"github.com/enterprizesoftware/rate-counter"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"slices"
	"strconv"
	"strings"
	"time"
)

var screen tcell.Screen
var app *tview.Application
var table *tview.Table
var appClosed = NewManualResetEvent(true)
var stopUpdate = NewManualResetEvent(false)
var updateStopped = NewManualResetEvent(false)

const (
	rowActive = iota
	rowStalled
	rowRemoved
	rowHeader
)

type stateRow struct {
	row   *TrafficRow
	state int
	order int
}

func bytesFormat(rate *ratecounter.Rate) string {
	return humanize.Comma(int64(rate.Total()))
}

func rateFormat(rate *ratecounter.Rate) string {
	return strings.ReplaceAll(humanize.IBytes(uint64(rate.RatePer(1*time.Second))), "i", "")
}

func setCell(i, j int, s string, w int, left bool, state int) {
	align := tview.AlignRight
	if left {
		align = tview.AlignLeft
	}
	length := tview.TaggedStringWidth(s)
	if w > 0 {
		if length < w {
			if left {
				s += strings.Repeat(" ", w-length)
			} else {
				s = strings.Repeat(" ", w-length) + s
			}
		}
	} else if w < 0 {
		if length > -w {
			s = s[:-w-1] + "…"
		} else if length < -w {
			if left {
				s += strings.Repeat(" ", -w-length)
			} else {
				s = strings.Repeat(" ", -w-length) + s
			}
		}
	}
	if i > 0 && j == 1 {
		a := strings.Split(s, " ")
		if len(a) > 1 {
			a[1] = "[aqua]" + a[1] + "[-]"
		}
		if len(a) > 3 {
			a[3] = "[yellow]" + a[3] + "[-]"
		}
		s = strings.Join(a, " ")
	}
	s = " " + s + " "
	// style
	color := tcell.ColorWhite
	bgcolor := tcell.ColorBlack
	switch state {
	case rowActive:
		color = tcell.ColorGreen
	case rowStalled:
		color = tcell.ColorOrange
	case rowRemoved:
		color = tcell.ColorGrey
	case rowHeader:
		color = tcell.ColorBlack
		bgcolor = tcell.ColorAqua
	}
	// cell
	table.SetCell(i, j, table.GetCell(i, j).SetAlign(align).SetTextColor(color).SetBackgroundColor(bgcolor).SetText(s))
}

func setRow(row int, state int, urlWidth int, reqId string, url string, bytesSent string, bytesReceived string, bytesSentPerSecond string, bytesReceivedPerSecond string) {
	setCell(row, 0, reqId, 5, false, state)
	setCell(row, 1, url, -urlWidth, true, state)
	setCell(row, 2, bytesReceived, 15, false, state)
	setCell(row, 3, bytesSent, 15, false, state)
	setCell(row, 4, bytesReceivedPerSecond, 7, false, state)
	setCell(row, 5, bytesSentPerSecond, 7, false, state)
}

func appInit() {
	var err error

	// Create screen
	if screen, err = tcell.NewScreen(); err != nil {
		panic(err)
	}

	// Create table
	table = tview.NewTable().
		ScrollToBeginning().
		SetBorders(false).
		SetFixed(1, 0).
		SetSelectable(false, false).
		SetSeparator(tview.Borders.Vertical)
	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return nil
	})

	// Create application
	app = tview.NewApplication().SetScreen(screen)
	app.SetRoot(table, true)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q', 'Q':
				IfApp(func() {
					appIsRunning = false
				})
				close(quitUI)
				app.Stop()
				//case ' ':
				//	IfApp(func() {
				//		appIsRunning = false
				//	})
				//	app.Stop()
			}
		case tcell.KeyCtrlC:
			IfApp(func() {
				appIsRunning = false
			})
			close(quitUI)
			app.Stop()
		//case tcell.KeyEsc, tcell.KeyTab, tcell.KeyDown, tcell.KeyLeft, tcell.KeyUp, tcell.KeyRight:
		//	IfApp(func() {
		//		appIsRunning = false
		//	})
		//	app.Stop()
		default:
		}
		return nil
	})
}

func appRun() {
	appClosed.Reset() // Run application
	defer appClosed.Signal()
	updateStopped.Reset()
	// start update in background
	go appUpdate()
	// start app ui
	if err := app.Run(); err != nil {
		panic(err)
	}
	// ensure update is stopped so we can nil app
	stopUpdate.Signal()
	updateStopped.Wait()
	app = nil
}

func appClose() {
	IfApp(func() {
		app.QueueEvent(tcell.NewEventKey(tcell.KeyEsc, 0, tcell.ModNone))
	})
}

func appKeyNoLock(b byte) {
	app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, rune(b), tcell.ModNone))
}

func appUpdate() {
	defer updateStopped.Signal()
	stopUpdate.Reset()
	ticker := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-stopUpdate.c:
			return
		case <-quitUI:
			return
		case <-ticker.C:
			IfApp(func() {
				app.QueueUpdateDraw(func() {
					// update the table with the new data
					screenWidth, screenHeight := screen.Size()
					totalWidth := 5 + 15 + 15 + 7 + 7 + 15 + 2
					urlWidth := screenWidth - totalWidth
					if urlWidth < 20 {
						urlWidth = 20
					}
					setRow(0, rowHeader, urlWidth, "ID", "URL", "RECV", "SENT", "RECV/S", "SENT/S")
					trafficRows := TrafficData.RowsCopy()
					rowsToDisplay := len(trafficRows)
					if rowsToDisplay+1 >= screenHeight {
						rowsToDisplay = screenHeight - 1
					}
					stateRows := make([]*stateRow, rowsToDisplay)
					i := 0
					for _, row := range slices.Backward(trafficRows) {
						if i >= rowsToDisplay {
							break
						}
						state := rowActive
						order := 0
						if row.Removed.IsZero() {
							updated := row.LastSend
							if row.LastReceive.After(updated) {
								updated = row.LastReceive
							}
							if time.Since(updated) > 1*time.Second {
								state = rowStalled
							}
						} else {
							state = rowRemoved
							order = 1
						}
						stateRows[i] = &stateRow{row: row, state: state, order: order}
						i++
					}
					slices.SortStableFunc(stateRows, func(r1, r2 *stateRow) int {
						switch {
						case r1.order < r2.order:
							return -1
						case r1.order > r2.order:
							return 1
						}
						return 0
					})
					for i, sr := range stateRows {
						state := sr.state
						row := sr.row
						setRow(i+1, state, urlWidth, strconv.Itoa(int(row.ReqId)), row.Url, bytesFormat(row.BytesSentPerSecond), bytesFormat(row.BytesReceivedPerSecond), rateFormat(row.BytesSentPerSecond), rateFormat(row.BytesReceivedPerSecond))
					}
					// remove any extra rows
					for i := table.GetRowCount() - 1; i > rowsToDisplay; i-- {
						table.RemoveRow(i)
					}
					// remove hidden rows
					for i := screenHeight; i < table.GetRowCount(); i++ {
						table.RemoveRow(i)
					}
				})
			})
		}
	}
}
