package telemetry

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRingBuffer_BatchSizeTrigger(t *testing.T) {
	var totalFlushed atomic.Int64
	flushedCh := make(chan struct{}, 1)

	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      100,
		BatchSize:     10,
		FlushInterval: 10 * time.Second, // Long interval to guarantee flush is triggered by batch size
		Handler: func(events []*ForensicEvent) error {
			totalFlushed.Add(int64(len(events)))
			if totalFlushed.Load() >= 10 {
				select {
				case flushedCh <- struct{}{}:
				default:
				}
			}
			return nil
		},
	})
	defer rb.Close()

	for i := 0; i < 10; i++ {
		ok := rb.Push(&ForensicEvent{EventID: "evt-test"})
		if !ok {
			t.Fatalf("failed to push event %d", i)
		}
	}

	select {
	case <-flushedCh:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatalf("expected batch size flush, but timed out (flushed: %d)", totalFlushed.Load())
	}

	if totalFlushed.Load() != 10 {
		t.Errorf("expected 10 flushed events, got %d", totalFlushed.Load())
	}
}

func TestRingBuffer_IntervalTrigger(t *testing.T) {
	var totalFlushed atomic.Int64
	flushedCh := make(chan struct{}, 1)

	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      100,
		BatchSize:     500, // Large batch size to guarantee flush is triggered by interval
		FlushInterval: 50 * time.Millisecond,
		Handler: func(events []*ForensicEvent) error {
			totalFlushed.Add(int64(len(events)))
			select {
			case flushedCh <- struct{}{}:
			default:
			}
			return nil
		},
	})
	defer rb.Close()

	rb.Push(&ForensicEvent{EventID: "evt-interval-1"})
	rb.Push(&ForensicEvent{EventID: "evt-interval-2"})

	select {
	case <-flushedCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatalf("expected interval flush, but timed out")
	}

	if totalFlushed.Load() != 2 {
		t.Errorf("expected 2 flushed events, got %d", totalFlushed.Load())
	}
}

func TestRingBuffer_SaturationAndDrop(t *testing.T) {
	// Ring buffer with small capacity and no handler worker reading
	rb := &RingBuffer{
		ch:            make(chan *ForensicEvent, 5),
		capacity:      5,
		batchSize:     10,
		flushInterval: time.Hour,
	}

	for i := 0; i < 5; i++ {
		if !rb.Push(&ForensicEvent{EventID: "evt-fill"}) {
			t.Fatalf("expected push %d to succeed", i)
		}
	}

	// Next 3 pushes should be dropped without blocking
	for i := 0; i < 3; i++ {
		if rb.Push(&ForensicEvent{EventID: "evt-drop"}) {
			t.Fatalf("expected push %d to be dropped", i)
		}
	}

	if rb.Dropped() != 3 {
		t.Errorf("expected 3 dropped events, got %d", rb.Dropped())
	}
	if rb.Enqueued() != 5 {
		t.Errorf("expected 5 enqueued events, got %d", rb.Enqueued())
	}
}

func TestRingBuffer_DrainOnClose(t *testing.T) {
	var totalFlushed atomic.Int64

	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      1000,
		BatchSize:     500,
		FlushInterval: time.Hour,
		Handler: func(events []*ForensicEvent) error {
			totalFlushed.Add(int64(len(events)))
			return nil
		},
	})

	const numEvents = 75
	for i := 0; i < numEvents; i++ {
		rb.Push(&ForensicEvent{EventID: "evt-drain"})
	}

	// Close must drain remaining 75 events before returning
	if err := rb.Close(); err != nil {
		t.Fatalf("error closing ring buffer: %v", err)
	}

	if totalFlushed.Load() != numEvents {
		t.Errorf("expected %d flushed events on close, got %d", numEvents, totalFlushed.Load())
	}
}

func TestRingBuffer_ConcurrentHighQPS(t *testing.T) {
	var totalFlushed atomic.Int64

	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      50000,
		BatchSize:     100,
		FlushInterval: 10 * time.Millisecond,
		Handler: func(events []*ForensicEvent) error {
			totalFlushed.Add(int64(len(events)))
			return nil
		},
	})

	const numGoroutines = 20
	const eventsPerGoroutine = 500

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				rb.Push(&ForensicEvent{EventID: "evt-concurrent"})
			}
		}()
	}

	wg.Wait()
	_ = rb.Close()

	totalExpected := int64(numGoroutines * eventsPerGoroutine)
	totalProcessed := totalFlushed.Load() + int64(rb.Dropped())

	if totalProcessed != totalExpected {
		t.Errorf("expected sum of flushed (%d) + dropped (%d) == %d, got %d",
			totalFlushed.Load(), rb.Dropped(), totalExpected, totalProcessed)
	}
}

func BenchmarkRingBuffer_Push(b *testing.B) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      100000,
		BatchSize:     500,
		FlushInterval: 100 * time.Millisecond,
		Handler: func(events []*ForensicEvent) error {
			return nil
		},
	})
	defer rb.Close()

	event := &ForensicEvent{
		EventID:  "bench-evt",
		ClientIP: "127.0.0.1",
		Host:     "localhost",
		Path:     "/",
		Method:   "GET",
		Action:   "allow",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rb.Push(event)
		}
	})
}
