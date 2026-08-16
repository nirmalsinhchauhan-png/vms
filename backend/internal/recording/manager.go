// Package recording implements the FFmpeg recording pipeline: one
// supervised ffmpeg process per camera with an active continuous
// recording_schedule, writing 10-second HLS segments to disk, tracked into
// recording_segments as they're finalized, cleaned up on a retention timer.
//
// This is deliberately separate from the go2rtc live-view pipeline
// (internal/go2rtc) — mainstream (recording) and substream (live) are two
// independent paths per the architecture's core mainstream/substream split.
package recording

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	appcrypto "github.com/siliconsignals/vms/backend/internal/crypto"
)

type Manager struct {
	dbPool         *pgxpool.Pool
	storageRoot    string
	segDurationSec int
	ffmpegLogLevel string
	reconcileEvery time.Duration
	credKey        appcrypto.Key
	segWatch       *SegmentWatcher

	mu         sync.Mutex
	workers    map[string]*cameraWorker
	reconcileC chan struct{}
}

func NewManager(dbPool *pgxpool.Pool, storageRoot string, segDurationSec int, ffmpegLogLevel string, reconcileEvery time.Duration, credKey appcrypto.Key, segWatch *SegmentWatcher) *Manager {
	return &Manager{
		dbPool:         dbPool,
		storageRoot:    storageRoot,
		segDurationSec: segDurationSec,
		ffmpegLogLevel: ffmpegLogLevel,
		reconcileEvery: reconcileEvery,
		credKey:        credKey,
		segWatch:       segWatch,
		workers:        make(map[string]*cameraWorker),
		reconcileC:     make(chan struct{}, 1),
	}
}

// Run blocks until ctx is cancelled, reconciling on a timer and whenever
// TriggerReconcile is called, then stops every worker before returning.
func (m *Manager) Run(ctx context.Context) {
	m.reconcile(ctx)

	t := time.NewTicker(m.reconcileEvery)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			m.reconcile(ctx)
		case <-m.reconcileC:
			m.reconcile(ctx)
		case <-ctx.Done():
			m.stopAll()
			return
		}
	}
}

// TriggerReconcile asks for an out-of-cycle reconcile — call this
// best-effort from camera create/update/delete handlers so a change takes
// effect immediately rather than waiting for the next timer tick.
func (m *Manager) TriggerReconcile() {
	select {
	case m.reconcileC <- struct{}{}:
	default: // a reconcile is already pending; no need to queue another
	}
}

func (m *Manager) reconcile(ctx context.Context) {
	desired, err := m.loadDesiredSources(ctx)
	if err != nil {
		log.Printf("recording: reconcile: load cameras: %v", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	desiredIDs := make(map[string]cameraSource, len(desired))
	for _, s := range desired {
		desiredIDs[s.CameraID] = s
	}

	// Stop workers that are no longer wanted, or whose config changed
	// (fingerprint mismatch) — the latter is what makes a camera PATCH
	// (new mainstream_uri or credentials) actually take effect instead of
	// the worker silently running against stale config until it crashes.
	for id, w := range m.workers {
		src, stillWanted := desiredIDs[id]
		if !stillWanted || src.fingerprint() != w.fingerprint {
			w.stop()
			m.segWatch.UnwatchCamera(id)
			delete(m.workers, id)
		}
	}

	// Start anything newly wanted (or just stopped above for a restart).
	for id, src := range desiredIDs {
		if _, running := m.workers[id]; running {
			continue
		}
		w, err := startWorker(ctx, src, m.storageRoot, m.segDurationSec, m.ffmpegLogLevel, m.credKey, m.segWatch)
		if err != nil {
			log.Printf("recording: start worker for camera %s: %v", id, err)
			continue
		}
		m.workers[id] = w
	}
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, w := range m.workers {
		w.stop()
		m.segWatch.UnwatchCamera(id)
		delete(m.workers, id)
	}
}

func (m *Manager) loadDesiredSources(ctx context.Context) ([]cameraSource, error) {
	rows, err := m.dbPool.Query(ctx, `
		SELECT c.id, c.mainstream_uri, c.credential_enc, c.credential_nonce
		FROM cameras c
		JOIN recording_schedules rs ON rs.camera_id = c.id
		WHERE rs.mode = 'continuous' AND c.status != 'disabled'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []cameraSource
	for rows.Next() {
		var s cameraSource
		if err := rows.Scan(&s.CameraID, &s.MainstreamURI, &s.CredEnc, &s.CredNonce); err != nil {
			log.Printf("recording: reconcile: scan camera row: %v", err)
			continue
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
