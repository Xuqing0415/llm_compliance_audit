package stream

import (
	"sync"
)

type SlidingWindow struct {
	mu             sync.Mutex
	buffer         []rune
	maxSize        int
	flushThreshold int
	flushOffset    int
}

func NewSlidingWindow(maxSize, flushThreshold int) *SlidingWindow {
	return &SlidingWindow{
		buffer:         make([]rune, 0, maxSize),
		maxSize:        maxSize,
		flushThreshold: flushThreshold,
		flushOffset:    0,
	}
}

func (sw *SlidingWindow) Append(content string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	runes := []rune(content)
	sw.buffer = append(sw.buffer, runes...)

	if len(sw.buffer) > sw.maxSize {
		overflow := len(sw.buffer) - sw.maxSize
		sw.buffer = sw.buffer[overflow:]
		if sw.flushOffset > overflow {
			sw.flushOffset -= overflow
		} else {
			sw.flushOffset = 0
		}
	}
}

func (sw *SlidingWindow) GetCurrentBuffer() string {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	return string(sw.buffer)
}

func (sw *SlidingWindow) GetUnflushedBuffer() string {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.flushOffset >= len(sw.buffer) {
		return ""
	}

	return string(sw.buffer[sw.flushOffset:])
}

func (sw *SlidingWindow) GetFlushedContent() string {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.flushOffset == 0 {
		return ""
	}

	return string(sw.buffer[:sw.flushOffset])
}

func (sw *SlidingWindow) Flush() (string, bool) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if len(sw.buffer) - sw.flushOffset < sw.flushThreshold {
		return "", false
	}

	toFlush := sw.buffer[sw.flushOffset:sw.flushOffset+sw.flushThreshold]
	sw.flushOffset += sw.flushThreshold

	return string(toFlush), true
}

func (sw *SlidingWindow) FlushAll() string {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	result := string(sw.buffer[sw.flushOffset:])
	sw.flushOffset = len(sw.buffer)

	return result
}

func (sw *SlidingWindow) Size() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	return len(sw.buffer)
}

func (sw *SlidingWindow) UnflushedSize() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	return len(sw.buffer) - sw.flushOffset
}