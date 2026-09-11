package pipeline

import (
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type LatencyRecord struct {
	Duration  time.Duration
	Timestamp time.Time
}

type DetectorStats struct {
	Name         string
	TotalCount   int64
	MatchCount   int64
	Latencies    []time.Duration
	MaxLatency   time.Duration
	MinLatency   time.Duration
	TotalLatency time.Duration
}

type StatsCollector struct {
	mu              sync.RWMutex
	detectorStats   map[string]*DetectorStats
	ringBufferSize  int
	startTime       time.Time
	totalRequests   int64
	blockedRequests int64
	allowedRequests int64
}

func NewStatsCollector(bufferSize int) *StatsCollector {
	return &StatsCollector{
		detectorStats:  make(map[string]*DetectorStats),
		ringBufferSize: bufferSize,
		startTime:      time.Now(),
	}
}

func (sc *StatsCollector) RecordLatency(detectorName string, duration time.Duration, matched bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, ok := sc.detectorStats[detectorName]; !ok {
		sc.detectorStats[detectorName] = &DetectorStats{
			Name:       detectorName,
			Latencies:  make([]time.Duration, 0),
			MaxLatency: 0,
			MinLatency: time.Hour,
		}
	}

	stats := sc.detectorStats[detectorName]
	stats.TotalCount++

	if matched {
		stats.MatchCount++
	}

	stats.Latencies = append(stats.Latencies, duration)
	if len(stats.Latencies) > sc.ringBufferSize {
		stats.Latencies = stats.Latencies[1:]
	}

	stats.TotalLatency += duration

	if duration > stats.MaxLatency {
		stats.MaxLatency = duration
	}

	if duration < stats.MinLatency {
		stats.MinLatency = duration
	}
}

func (sc *StatsCollector) RecordRequest(action string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.totalRequests++

	switch action {
	case "BLOCK":
		sc.blockedRequests++
	case "ALLOW":
		sc.allowedRequests++
	}
}

func (sc *StatsCollector) GetDetectorStats(detectorName string) *DetectorStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats, ok := sc.detectorStats[detectorName]
	if !ok {
		return nil
	}

	return sc.copyStats(stats)
}

func (sc *StatsCollector) GetAllStats() map[string]*DetectorStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make(map[string]*DetectorStats)
	for name, stats := range sc.detectorStats {
		result[name] = sc.copyStats(stats)
	}

	return result
}

func (sc *StatsCollector) copyStats(stats *DetectorStats) *DetectorStats {
	return &DetectorStats{
		Name:         stats.Name,
		TotalCount:   stats.TotalCount,
		MatchCount:   stats.MatchCount,
		Latencies:    append([]time.Duration(nil), stats.Latencies...),
		MaxLatency:   stats.MaxLatency,
		MinLatency:   stats.MinLatency,
		TotalLatency: stats.TotalLatency,
	}
}

func (sc *StatsCollector) GetP99Latency(detectorName string) time.Duration {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats, ok := sc.detectorStats[detectorName]
	if !ok || len(stats.Latencies) == 0 {
		return 0
	}

	sorted := make([]time.Duration, len(stats.Latencies))
	copy(sorted, stats.Latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	index := int(float64(len(sorted)) * 0.99)
	if index >= len(sorted) {
		index = len(sorted) - 1
	}

	return sorted[index]
}

func (sc *StatsCollector) GetAverageLatency(detectorName string) time.Duration {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats, ok := sc.detectorStats[detectorName]
	if !ok || stats.TotalCount == 0 {
		return 0
	}

	return stats.TotalLatency / time.Duration(stats.TotalCount)
}

func (sc *StatsCollector) GetTotalRequests() int64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return sc.totalRequests
}

func (sc *StatsCollector) GetBlockedRequests() int64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return sc.blockedRequests
}

func (sc *StatsCollector) GetAllowedRequests() int64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return sc.allowedRequests
}

func (sc *StatsCollector) GetUptime() time.Duration {
	return time.Since(sc.startTime)
}

func (sc *StatsCollector) Reset() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.detectorStats = make(map[string]*DetectorStats)
	sc.startTime = time.Now()
	sc.totalRequests = 0
	sc.blockedRequests = 0
	sc.allowedRequests = 0

	logrus.Info("Stats collector reset")
}
