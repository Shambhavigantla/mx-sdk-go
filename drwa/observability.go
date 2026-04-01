package drwa

import "sync"

type observability struct {
	mut      sync.Mutex
	counters map[string]uint64
}

var sdkMetrics = newObservability()

func newObservability() *observability {
	return &observability{
		counters: make(map[string]uint64),
	}
}

func (o *observability) increment(metric string) {
	o.mut.Lock()
	o.counters[metric]++
	o.mut.Unlock()
}

func (o *observability) snapshot() map[string]uint64 {
	o.mut.Lock()
	defer o.mut.Unlock()

	snapshot := make(map[string]uint64, len(o.counters))
	for key, value := range o.counters {
		snapshot[key] = value
	}

	return snapshot
}

func (o *observability) reset() {
	o.mut.Lock()
	o.counters = make(map[string]uint64)
	o.mut.Unlock()
}

func recordMetric(metric string) {
	sdkMetrics.increment(metric)
}

func SnapshotMetrics() map[string]uint64 {
	return sdkMetrics.snapshot()
}

func ResetMetrics() {
	sdkMetrics.reset()
}
