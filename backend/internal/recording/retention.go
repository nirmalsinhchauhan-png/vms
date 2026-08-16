package recording

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const retentionBatchSize = 500

// RunRetentionSweep deletes expired recording_segments (and their backing
// files) on a timer until ctx is cancelled. Call this in its own goroutine
// alongside Manager.Run.
func RunRetentionSweep(ctx context.Context, dbPool *pgxpool.Pool, interval time.Duration, storageRoot string) {
	sweepStaleTmp(storageRoot, interval) // once at startup, in case of a prior hard kill
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			sweepExpiredSegments(ctx, dbPool, storageRoot)
			sweepStaleTmp(storageRoot, interval)
		case <-ctx.Done():
			return
		}
	}
}

// sweepExpiredSegments deletes the file first, then the DB row — never the
// reverse. If the file delete fails (permission, I/O error, busy handle)
// the row is deliberately left in place so the same WHERE clause matches
// it again next sweep; deleting the row first and then failing to delete
// the file would leave a permanent, silent disk-space leak with nothing
// left to ever revisit that file.
func sweepExpiredSegments(ctx context.Context, dbPool *pgxpool.Pool, storageRoot string) {
	for {
		rows, err := dbPool.Query(ctx, `
			SELECT rs.id, rs.file_path
			FROM recording_segments rs
			JOIN recording_schedules sched ON sched.camera_id = rs.camera_id
			WHERE rs.started_at < now() - (sched.retention_days || ' days')::interval
			ORDER BY rs.started_at
			LIMIT $1
		`, retentionBatchSize)
		if err != nil {
			log.Printf("recording: retention: query expired segments: %v", err)
			return
		}

		type expiredRow struct{ id, filePath string }
		var batch []expiredRow
		for rows.Next() {
			var r expiredRow
			if err := rows.Scan(&r.id, &r.filePath); err != nil {
				log.Printf("recording: retention: scan: %v", err)
				continue
			}
			batch = append(batch, r)
		}
		rows.Close()

		if len(batch) == 0 {
			return
		}

		for _, r := range batch {
			full := filepath.Join(storageRoot, r.filePath)
			if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
				log.Printf("recording: retention: delete file %s: %v (row kept, retry next sweep)", full, err)
				continue
			}
			_ = os.Remove(strings.TrimSuffix(full, ".ts") + ".m3u8") // companion trivial playlist, best-effort

			if _, err := dbPool.Exec(ctx, `DELETE FROM recording_segments WHERE id = $1`, r.id); err != nil {
				log.Printf("recording: retention: delete row %s: %v (file already gone, will retry)", r.id, err)
			}
		}

		if len(batch) < retentionBatchSize {
			return
		}
	}
}

// sweepStaleTmp removes orphaned "*.ts.tmp" files left behind by a
// hard-killed ffmpeg process (a clean stop always lets ffmpeg finish its
// SIGTERM-triggered rename; only a SIGKILL or crash leaves one of these).
// A file recently modified is presumably still being actively written by a
// live worker, not orphaned — only remove ones stale well past what a
// normal segment write could take.
func sweepStaleTmp(storageRoot string, sweepInterval time.Duration) {
	matches, err := filepath.Glob(filepath.Join(storageRoot, "*", "*", "*.ts.tmp"))
	if err != nil {
		log.Printf("recording: retention: glob stale .tmp files: %v", err)
		return
	}
	staleAfter := sweepInterval
	if staleAfter < 5*time.Minute {
		staleAfter = 5 * time.Minute
	}
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > staleAfter {
			if err := os.Remove(m); err != nil {
				log.Printf("recording: retention: remove stale tmp %s: %v", m, err)
			}
		}
	}
}
