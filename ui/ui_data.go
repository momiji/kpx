package ui

import (
	"github.com/enterprizesoftware/rate-counter"
	"slices"
	"sync"
	"time"
)

type TrafficRow struct {
	ReqId                  int32
	Url                    string
	BytesSent              int64
	BytesReceived          int64
	BytesSentPerSecond     *ratecounter.Rate
	BytesReceivedPerSecond *ratecounter.Rate
}

type TrafficTable struct {
	table []*TrafficRow
	lock  *sync.RWMutex
}

func NewTraffic(reqId int32, url string) *TrafficRow {
	return &TrafficRow{
		ReqId:                  reqId,
		Url:                    url,
		BytesSentPerSecond:     ratecounter.New(100*time.Millisecond, 5*time.Second),
		BytesReceivedPerSecond: ratecounter.New(100*time.Millisecond, 5*time.Second),
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

var Traffic = TrafficTable{
	table: make([]*TrafficRow, 0),
	lock:  &sync.RWMutex{},
}
