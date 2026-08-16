package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jackc/pgx/v5/pgxpool"
)

type hashJob struct {
	id   string
	path string
}

// SegmentWatcher tracks FFmpeg's HLS output on disk and inserts a
// recording_segments row the moment each .ts file is finalized.
//
// Finalize signal: ffmpeg is launched with `-hls_flags temp_file`, so it
// writes every segment as "<name>.ts.tmp" and atomically renames to
// "<name>.ts" only once fully written and closed. On Linux, inotify (what
// fsnotify wraps) reports that same-directory rename's destination as a
// Create event on the final path — so a fsnotify.Create on a path ending
// ".ts" (never ".ts.tmp") is the one, sufficient "segment finalized"
// signal. No custom -hls_segment_filename scripting is needed.
type SegmentWatcher struct {
	dbPool   *pgxpool.Pool
	root     string
	nominal  time.Duration
	watcher  *fsnotify.Watcher
	hashJobs chan hashJob
}

var segmentPathRe = regexp.MustCompile(`^([0-9a-fA-F-]{36})/\d{4}-\d{2}-\d{2}/seg_(\d{8})_(\d{6})\.ts$`)

// groupWritableMode is setgid + rwxrwx--- — group_add/SECRETS_GID (the
// same mechanism the JWT secrets use) gives the container's non-root user
// supplementary membership in the host's own GID, and setgid is what makes
// every subdirectory created underneath (by this code, or by ffmpeg's own
// -strftime_mkdir) keep inheriting that group instead of the container
// user's own.
//
// Deliberately os.ModeSetgid|0770, not the raw literal 0o2770: Go's
// os.FileMode does NOT use traditional Unix octal bit positions for
// setuid/setgid/sticky — those live in separate high bits of FileMode, so a
// raw "0o2770" literal's "2" doesn't map to Go's ModeSetgid flag at all.
// Passed as a bare numeric literal, it silently collapsed to plain 0770 at
// the actual chmod(2)/mkdir(2) syscall — permission bits landed, setgid
// never did. Confirmed by comparing this code's actual on-disk result
// against a manual `chmod 2770` in a shell (which interprets the octal
// argument directly, no Go translation layer, and worked correctly) —
// that mismatch is what exposed this.
//
// mkdirGroupWritable chmods explicitly after creating a *new* directory,
// because mkdir(2) is subject to the process umask (Alpine's default masks
// out the group-write bit — verified separately: MkdirAll alone dropped
// exactly that bit) while chmod(2) is not. It deliberately skips chmod on a
// directory that already existed: chmod requires *owning* the path, not
// just having group access to it, and the storage root is created and
// chmod'd host-side by `make init` (owned by the host user, not the
// container's) — retrying that chmod as the container's own user would
// just fail with EPERM on something that's already correctly set up.
func mkdirGroupWritable(path string) error {
	_, statErr := os.Stat(path)
	existedAlready := statErr == nil

	if err := os.MkdirAll(path, groupWritableMode); err != nil {
		return err
	}
	if existedAlready {
		return nil
	}
	return os.Chmod(path, groupWritableMode)
}

// "Other" gets r-x, not just the owner/group rwx: nginx serves these files
// from its own container, and its worker processes drop from root to the
// `nginx` system account per nginx.conf's `user nginx;` directive — that
// internal setuid/setgid call resets the process's supplementary group
// list, which discards Docker's group_add/SECRETS_GID entirely (confirmed:
// `group_add` alone left the actual worker process with only its own
// group, not the host's). group_add only survives for a process that
// never re-execs/drops privilege internally, like the backend's Go binary
// — nginx's worker model doesn't qualify. The real access control on these
// files is the HMAC-signed segment token nginx's auth_request enforces at
// the HTTP layer (internal.go), not Unix permissions, so world-readable
// directories here cost nothing security-wise and sidestep the whole
// privilege-drop problem.
const groupWritableMode = os.ModeSetgid | 0o775

func NewSegmentWatcher(dbPool *pgxpool.Pool, root string, nominal time.Duration) (*SegmentWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("recording: create fsnotify watcher: %w", err)
	}
	// A no-op in the normal flow, since `make init` already creates and
	// chmods this directory host-side before the container ever starts —
	// this only matters as a fallback if that step was skipped.
	if err := mkdirGroupWritable(root); err != nil {
		w.Close()
		return nil, fmt.Errorf("recording: create storage root: %w", err)
	}
	return &SegmentWatcher{
		dbPool:   dbPool,
		root:     root,
		nominal:  nominal,
		watcher:  w,
		hashJobs: make(chan hashJob, 64),
	}, nil
}

// WatchCamera adds a watch on the camera's own directory. Must be called
// before the camera's ffmpeg process is started — if ffmpeg creates its
// first dated subdirectory before this watch exists, that directory's own
// creation event (needed to add a watch on *it*) is missed entirely, and
// every segment written into it that day would be invisible.
func (sw *SegmentWatcher) WatchCamera(cameraID string) error {
	dir := filepath.Join(sw.root, cameraID)
	if err := mkdirGroupWritable(dir); err != nil {
		return fmt.Errorf("recording: create camera dir: %w", err)
	}
	if err := sw.watcher.Add(dir); err != nil {
		return fmt.Errorf("recording: watch camera dir: %w", err)
	}
	return nil
}

func (sw *SegmentWatcher) UnwatchCamera(cameraID string) {
	_ = sw.watcher.Remove(filepath.Join(sw.root, cameraID))
}

// Run processes filesystem events until ctx is done. Start it once, in its
// own goroutine, before any camera worker starts.
func (sw *SegmentWatcher) Run(ctx context.Context) {
	const hashWorkers = 2
	for i := 0; i < hashWorkers; i++ {
		go sw.hashWorker()
	}
	defer close(sw.hashJobs)

	for {
		select {
		case ev, ok := <-sw.watcher.Events:
			if !ok {
				return
			}
			sw.handleEvent(ev)
		case err, ok := <-sw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("recording: fsnotify error: %v", err)
		case <-ctx.Done():
			sw.watcher.Close()
			return
		}
	}
}

func (sw *SegmentWatcher) handleEvent(ev fsnotify.Event) {
	if ev.Op&fsnotify.Create == 0 {
		return
	}
	info, err := os.Stat(ev.Name)
	if err != nil {
		return // file already gone by the time we looked — rare race, safe to skip
	}
	if info.IsDir() {
		// A new YYYY-MM-DD directory just appeared (ffmpeg's -strftime_mkdir
		// rolling to a new day). fsnotify is not recursive — it needs its
		// own explicit watch or every segment written into it is invisible.
		if err := sw.watcher.Add(ev.Name); err != nil {
			log.Printf("recording: watch new date dir %s: %v", ev.Name, err)
		}
		return
	}
	if strings.HasSuffix(ev.Name, ".ts") {
		sw.finalizeSegment(ev.Name)
	}
	// live_index.m3u8 / *.m3u8.tmp / *.ts.tmp creates are ignored here —
	// the rolling live_index.m3u8 ffmpeg itself writes is never served to
	// clients (see the recording routes' playback design).
}

func (sw *SegmentWatcher) finalizeSegment(path string) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("recording: stat finalized segment %s: %v", path, err)
		return
	}

	relPath, err := filepath.Rel(sw.root, path)
	if err != nil {
		log.Printf("recording: segment path %s not under storage root: %v", path, err)
		return
	}
	cameraID, startedAt, err := parseSegmentPath(relPath)
	if err != nil {
		log.Printf("recording: could not parse segment path %s: %v", relPath, err)
		return
	}

	durationMs := int(time.Since(startedAt).Milliseconds())
	if durationMs <= 0 || durationMs > int(10*sw.nominal.Milliseconds()) {
		// Clock skew, or the watcher attached mid-segment — fall back to
		// the configured nominal duration rather than storing a bogus value.
		durationMs = int(sw.nominal.Milliseconds())
	}

	var id string
	err = sw.dbPool.QueryRow(context.Background(), `
		INSERT INTO recording_segments (camera_id, file_path, started_at, duration_ms, size_bytes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, cameraID, relPath, startedAt, durationMs, info.Size()).Scan(&id)
	if err != nil {
		log.Printf("recording: insert segment row for %s: %v", relPath, err)
		return
	}

	sw.writeTrivialPlaylist(path, durationMs)

	select {
	case sw.hashJobs <- hashJob{id: id, path: path}:
	default:
		log.Printf("recording: hash queue full, skipping checksum for segment %s", id)
	}
}

// writeTrivialPlaylist writes a static, one-entry HLS playlist next to the
// segment so a browser can actually play it — a raw .ts file can't be given
// to <video src=...>/hls.js directly. Stitching multiple segments across an
// arbitrary time range into one continuous playlist is deliberately out of
// scope this sprint; this is the whole playback surface for now.
func (sw *SegmentWatcher) writeTrivialPlaylist(segmentPath string, durationMs int) {
	targetDuration := (durationMs + 999) / 1000 // ceil to whole seconds, per the HLS spec's #EXT-X-TARGETDURATION
	playlist := fmt.Sprintf(
		"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:%d\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:%.3f,\n%s\n#EXT-X-ENDLIST\n",
		targetDuration, float64(durationMs)/1000.0, filepath.Base(segmentPath),
	)
	playlistPath := strings.TrimSuffix(segmentPath, ".ts") + ".m3u8"
	if err := os.WriteFile(playlistPath, []byte(playlist), 0o640); err != nil {
		log.Printf("recording: write playlist for %s: %v", segmentPath, err)
	}
}

func (sw *SegmentWatcher) hashWorker() {
	for job := range sw.hashJobs {
		sum, err := sha256File(job.path)
		if err != nil {
			log.Printf("recording: checksum segment %s: %v", job.path, err)
			continue
		}
		if _, err := sw.dbPool.Exec(context.Background(),
			`UPDATE recording_segments SET checksum_sha256 = $1 WHERE id = $2`, sum, job.id,
		); err != nil {
			log.Printf("recording: store checksum for segment %s: %v", job.id, err)
		}
	}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseSegmentPath extracts the camera ID and start time from a path of
// the form "<camera_id>/<YYYY-MM-DD>/seg_<YYYYMMDD>_<HHMMSS>.ts" (relative
// to the storage root) — the exact layout the ffmpeg command line in
// worker.go writes. The timestamp is parsed as UTC: worker.go forces
// TZ=UTC on the ffmpeg process specifically so strftime's filenames match
// this parsing unambiguously.
func parseSegmentPath(relPath string) (cameraID string, startedAt time.Time, err error) {
	m := segmentPathRe.FindStringSubmatch(filepath.ToSlash(relPath))
	if m == nil {
		return "", time.Time{}, fmt.Errorf("recording: path %q does not match expected segment layout", relPath)
	}
	cameraID = m[1]
	startedAt, err = time.ParseInLocation("20060102_150405", m[2]+"_"+m[3], time.UTC)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("recording: parse segment timestamp: %w", err)
	}
	return cameraID, startedAt, nil
}
