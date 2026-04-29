package ui

import (
	"slices"
	"sync"
	"time"

	"github.com/momiji/kpx/transport"
)

type TrafficRow struct {
	ReqId   int32
	Url     string
	Conn    *transport.TrafficConn
	Removed time.Time
}

type TrafficTable struct {
	table []*TrafficRow
	lock  *sync.RWMutex
}

func NewTrafficRow(reqId int32, url string, conn *transport.TrafficConn) *TrafficRow {
	return &TrafficRow{
		ReqId:   reqId,
		Url:     url,
		Conn:    conn,
		Removed: time.Time{},
	}
}

func (t *TrafficTable) Add(row *TrafficRow) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.table = append(t.table, row)
}

func (t *TrafficTable) Count() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return len(t.table)
}

func (t *TrafficTable) DeleteAt(pos int) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.table = slices.Delete(t.table, pos, pos+1)
}

func (t *TrafficTable) Get(pos int) *TrafficRow {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.table[pos]
}

func (t *TrafficTable) RowsCopy() []*TrafficRow {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return slices.Clone(t.table)
}

func (t *TrafficTable) Remove(row *TrafficRow) {
	row.Removed = time.Now()
}

func (t *TrafficTable) RemoveDead() {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.table = slices.DeleteFunc(t.table, func(row *TrafficRow) bool {
		return !row.Removed.IsZero() && time.Since(row.Removed) > 30*time.Second
	})
}

var TrafficData = TrafficTable{
	table: make([]*TrafficRow, 0),
	lock:  &sync.RWMutex{},
}
