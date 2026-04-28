package server

import "testing"

func TestErrorLogLimiter_WindowedSuppression(t *testing.T) {
	var limiter errorLogLimiter

	if ok, suppressed := limiter.shouldLogUnix(100); !ok || suppressed != 0 {
		t.Fatalf("first event: ok=%v suppressed=%d, want ok=true suppressed=0", ok, suppressed)
	}
	if ok, suppressed := limiter.shouldLogUnix(100); ok || suppressed != 0 {
		t.Fatalf("second same-second event: ok=%v suppressed=%d, want ok=false suppressed=0", ok, suppressed)
	}
	if ok, suppressed := limiter.shouldLogUnix(100); ok || suppressed != 0 {
		t.Fatalf("third same-second event: ok=%v suppressed=%d, want ok=false suppressed=0", ok, suppressed)
	}

	if ok, suppressed := limiter.shouldLogUnix(101); !ok || suppressed != 2 {
		t.Fatalf("first next-second event: ok=%v suppressed=%d, want ok=true suppressed=2", ok, suppressed)
	}
	if ok, suppressed := limiter.shouldLogUnix(101); ok || suppressed != 0 {
		t.Fatalf("second next-second event: ok=%v suppressed=%d, want ok=false suppressed=0", ok, suppressed)
	}
	if ok, suppressed := limiter.shouldLogUnix(102); !ok || suppressed != 1 {
		t.Fatalf("first following-second event: ok=%v suppressed=%d, want ok=true suppressed=1", ok, suppressed)
	}
}
