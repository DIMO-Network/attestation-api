package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// TransferStats tracks the progress of the manual transfer
type TransferStats struct {
	mu             sync.RWMutex
	TotalSubjects  int           `json:"total_subjects"`
	Processed      int           `json:"processed"`
	Successful     int           `json:"successful"`
	Failed         int           `json:"failed"`
	Skipped        int           `json:"skipped"`
	StartTime      time.Time     `json:"start_time"`
	LastUpdateTime time.Time     `json:"last_update_time"`
	Errors         []string      `json:"errors"`
	FailedSubjects []string      `json:"failed_subjects"`
	CurrentSubject string        `json:"current_subject"`
	ProcessingTime time.Duration `json:"processing_time"`
}

func (ts *TransferStats) IncrementProcessed() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Processed++
	ts.LastUpdateTime = time.Now()
}

func (ts *TransferStats) IncrementSuccessful() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Successful++
	ts.LastUpdateTime = time.Now()
}

func (ts *TransferStats) IncrementFailed(subject string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Failed++
	ts.FailedSubjects = append(ts.FailedSubjects, subject)
	ts.LastUpdateTime = time.Now()
}

func (ts *TransferStats) IncrementSkipped() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Skipped++
	ts.LastUpdateTime = time.Now()
}

func (ts *TransferStats) AddError(err string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Errors = append(ts.Errors, err)
	ts.LastUpdateTime = time.Now()
}

func (ts *TransferStats) SetCurrentSubject(subject string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.CurrentSubject = subject
	ts.LastUpdateTime = time.Now()
}

func (ts *TransferStats) GetStats() TransferStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	stats := *ts
	stats.ProcessingTime = time.Since(ts.StartTime)
	return stats
}

func startStatsServer(port int, stats *TransferStats, logger zerolog.Logger) {
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats.GetStats())
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stats := stats.GetStats()
		html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Manual Transfer Stats</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .stat { margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 5px; }
        .progress { width: 100%%; background: #ddd; border-radius: 5px; }
        .progress-bar { height: 20px; background: #4CAF50; border-radius: 5px; text-align: center; line-height: 20px; color: white; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Manual Transfer Progress</h1>
    <div class="stat">
        <strong>Total Subjects:</strong> %d
    </div>
    <div class="stat">
        <strong>Processed:</strong> %d
    </div>
    <div class="stat">
        <strong>Successful:</strong> %d
    </div>
    <div class="stat">
        <strong>Failed:</strong> %d
    </div>
    <div class="stat">
        <strong>Skipped:</strong> %d
    </div>
    <div class="stat">
        <strong>Current Subject:</strong> %s
    </div>
    <div class="stat">
        <strong>Processing Time:</strong> %s
    </div>
    <div class="stat">
        <strong>Progress:</strong>
        <div class="progress">
            <div class="progress-bar" style="width: %.1f%%">%.1f%%</div>
        </div>
    </div>
    <div class="stat">
        <strong>Last Update:</strong> %s
    </div>
    <div class="stat">
        <strong>Errors:</strong>
        <ul>
`, stats.TotalSubjects, stats.Processed, stats.Successful, stats.Failed, stats.Skipped,
			stats.CurrentSubject, stats.ProcessingTime.Round(time.Second),
			float64(stats.Processed)/float64(stats.TotalSubjects)*100,
			float64(stats.Processed)/float64(stats.TotalSubjects)*100,
			stats.LastUpdateTime.Format("2006-01-02 15:04:05"))

		for _, err := range stats.Errors {
			html += fmt.Sprintf(`            <li class="error">%s</li>`, err)
		}
		html += `
        </ul>
    </div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})

	addr := ":" + strconv.Itoa(port)
	logger.Info().Str("addr", addr).Msg("Starting stats server")
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Error().Err(err).Msg("Stats server failed")
	}
}
