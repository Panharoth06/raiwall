package telemetry

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultRingBufferCapacity is the default queue size (10,000 events).
	DefaultRingBufferCapacity = 10000

	// DefaultBatchSize is the number of events after which an immediate batch flush triggers.
	DefaultBatchSize = 500

	// DefaultFlushInterval is the periodic interval for batch flushing.
	DefaultFlushInterval = 500 * time.Millisecond
)

// BatchSink represents any storage or dispatch engine that can process batches of events.
type BatchSink interface {
	SaveBatch(events []*ForensicEvent) error
}

// BatchHandler is a function callback that handles flushed event batches.
type BatchHandler func([]*ForensicEvent) error

// RingBufferConfig provides tuning parameters for the ring buffer.
type RingBufferConfig struct {
	Capacity      int
	BatchSize     int
	FlushInterval time.Duration
	Handler       BatchHandler
}

// RingBuffer is a high-throughput, non-blocking in-memory event buffer.
// It accepts events without blocking request goroutines and flushes batches asynchronously.
type RingBuffer struct {
	ch            chan *ForensicEvent
	capacity      int
	batchSize     int
	flushInterval time.Duration
	handler       BatchHandler

	dropped  atomic.Uint64
	enqueued atomic.Uint64
	flushed  atomic.Uint64

	stopCh chan struct{}
	doneCh chan struct{}
	wg     sync.WaitGroup
	closed atomic.Bool
}

// NewRingBuffer constructs and starts a RingBuffer with the given configuration.
func NewRingBuffer(cfg RingBufferConfig) *RingBuffer {
	capVal := cfg.Capacity
	if capVal <= 0 {
		capVal = DefaultRingBufferCapacity
	}
	batchVal := cfg.BatchSize
	if batchVal <= 0 {
		batchVal = DefaultBatchSize
	}
	intervalVal := cfg.FlushInterval
	if intervalVal <= 0 {
		intervalVal = DefaultFlushInterval
	}

	rb := &RingBuffer{
		ch:            make(chan *ForensicEvent, capVal),
		capacity:      capVal,
		batchSize:     batchVal,
		flushInterval: intervalVal,
		handler:       cfg.Handler,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	rb.wg.Add(1)
	go rb.worker()

	return rb
}

// Push attempts to enqueue a ForensicEvent into the ring buffer.
// It is strictly non-blocking: if the buffer is full, the event is safely dropped
// and the dropped counter is atomically incremented. Returns true if queued, false if dropped.
func (rb *RingBuffer) Push(event *ForensicEvent) bool {
	if event == nil || rb.closed.Load() {
		return false
	}

	select {
	case rb.ch <- event:
		rb.enqueued.Add(1)
		return true
	default:
		rb.dropped.Add(1)
		return false
	}
}

// Dropped returns the total number of dropped events due to buffer saturation.
func (rb *RingBuffer) Dropped() uint64 {
	return rb.dropped.Load()
}

// Enqueued returns the total number of successfully enqueued events.
func (rb *RingBuffer) Enqueued() uint64 {
	return rb.enqueued.Load()
}

// Flushed returns the total number of events successfully flushed.
func (rb *RingBuffer) Flushed() uint64 {
	return rb.flushed.Load()
}

// Capacity returns the buffer's capacity.
func (rb *RingBuffer) Capacity() int {
	return rb.capacity
}

// Close gracefully stops the worker, draining all remaining buffered events.
func (rb *RingBuffer) Close() error {
	if rb.closed.Swap(true) {
		<-rb.doneCh
		return nil
	}

	close(rb.stopCh)
	rb.wg.Wait()
	close(rb.doneCh)
	return nil
}

func (rb *RingBuffer) worker() {
	defer rb.wg.Done()

	ticker := time.NewTicker(rb.flushInterval)
	defer ticker.Stop()

	batch := make([]*ForensicEvent, 0, rb.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if rb.handler != nil {
			_ = rb.handler(batch)
		}
		rb.flushed.Add(uint64(len(batch)))
		batch = make([]*ForensicEvent, 0, rb.batchSize)
	}

	for {
		select {
		case event := <-rb.ch:
			batch = append(batch, event)
			if len(batch) >= rb.batchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-rb.stopCh:
			// Drain remaining events in channel before exit
			for {
				select {
				case event := <-rb.ch:
					batch = append(batch, event)
					if len(batch) >= rb.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}
