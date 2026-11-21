// Package metrics provides entropy, latency percentile, and crash-safe JSONL helpers.
package metrics

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// ShannonEntropy returns the Shannon entropy of data in bits per byte [0, 8].
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*10000) / 10000
}

// LatencyStats summarizes latency distribution in milliseconds.
type LatencyStats struct {
	Count  int     `json:"count"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
	MeanMs float64 `json:"mean_ms"`
}

// ComputeLatencyStats computes p50, p95, p99, max, and mean over samplesMs.
func ComputeLatencyStats(samplesMs []float64) LatencyStats {
	if len(samplesMs) == 0 {
		return LatencyStats{}
	}
	sorted := make([]float64, len(samplesMs))
	copy(sorted, samplesMs)
	slices.Sort(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}

	return LatencyStats{
		Count:  len(sorted),
		P50Ms:  round3(percentileSorted(sorted, 0.50)),
		P95Ms:  round3(percentileSorted(sorted, 0.95)),
		P99Ms:  round3(percentileSorted(sorted, 0.99)),
		MaxMs:  round3(sorted[len(sorted)-1]),
		MeanMs: round3(sum / float64(len(sorted))),
	}
}

func percentileSorted(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	idx := int(math.Ceil(q*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}

// SyncJSONLWriter appends JSON lines and calls Sync() on every line so SIGKILL
// preserves all completed entries.
type SyncJSONLWriter struct {
	mu sync.Mutex
	f  *os.File
}

// NewSyncJSONLWriter opens or truncates path for synced JSONL appending.
// If path is empty, returns a no-op writer.
func NewSyncJSONLWriter(path string) (*SyncJSONLWriter, error) {
	if path == "" {
		return &SyncJSONLWriter{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	return &SyncJSONLWriter{f: f}, nil
}

// WriteRecord marshals v as one JSON line, writes it, and flushes to storage.
func (w *SyncJSONLWriter) WriteRecord(v any) error {
	if w == nil || w.f == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(b); err != nil {
		return err
	}
	return w.f.Sync()
}

// Close closes the underlying file if open.
func (w *SyncJSONLWriter) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.f.Close()
	w.f = nil
	return err
}
