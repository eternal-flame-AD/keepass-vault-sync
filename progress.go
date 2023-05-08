package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

func StartProgress(ctx context.Context, interval time.Duration, total uint64) (increment func(int64)) {
	var last uint64
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				last := atomic.LoadUint64(&last)
				percent := float64(last) / float64(total) * 100
				log.Printf("Progress: %d/%d (%.2f%%)", last, total, percent)
			}
		}
	}()
	return func(increment int64) {
		if increment >= 0 {
			atomic.AddUint64(&last, uint64(increment))
		} else {
			atomic.AddUint64(&last, ^uint64(-increment-1))
		}
	}
}
