package recording

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/siliconsignals/vms/backend/internal/camera"
	appcrypto "github.com/siliconsignals/vms/backend/internal/crypto"
)

// cameraSource is everything a worker needs to launch and, if needed,
// restart ffmpeg for one camera.
type cameraSource struct {
	CameraID      string
	MainstreamURI string
	CredEnc       []byte
	CredNonce     []byte
}

// fingerprint identifies whether the source config has changed since the
// worker was launched — the manager uses this to detect a camera PATCH
// (new URI or credentials) and restart the worker instead of letting it
// keep running against stale config until it happens to crash on its own.
func (s cameraSource) fingerprint() string {
	return s.MainstreamURI + "|" + string(s.CredEnc) + "|" + string(s.CredNonce)
}

type cameraWorker struct {
	source      cameraSource
	fingerprint string
	cancel      context.CancelFunc
	done        chan struct{}
}

func startWorker(ctx context.Context, src cameraSource, storageRoot string, segDurationSec int, ffmpegLogLevel string, credKey appcrypto.Key, segWatch *SegmentWatcher) (*cameraWorker, error) {
	cameraDir := filepath.Join(storageRoot, src.CameraID)
	if err := mkdirGroupWritable(cameraDir); err != nil {
		return nil, err
	}
	// Ordering matters: the watch must exist before ffmpeg can create
	// anything in this directory, or an early segment/subdirectory event
	// is missed entirely (see segmentwatcher.go's WatchCamera doc).
	if err := segWatch.WatchCamera(src.CameraID); err != nil {
		return nil, err
	}

	workerCtx, cancel := context.WithCancel(ctx)
	w := &cameraWorker{
		source:      src,
		fingerprint: src.fingerprint(),
		cancel:      cancel,
		done:        make(chan struct{}),
	}

	go func() {
		defer close(w.done)
		supervise(workerCtx, src, cameraDir, segDurationSec, ffmpegLogLevel, credKey)
	}()

	return w, nil
}

func (w *cameraWorker) stop() {
	w.cancel()
	<-w.done
}

// supervise runs ffmpeg for one camera, restarting it with exponential
// backoff on crash, until ctx is cancelled (camera/schedule removed, or
// its config changed and the manager is replacing this worker).
func supervise(ctx context.Context, src cameraSource, cameraDir string, segDurationSec int, ffmpegLogLevel string, credKey appcrypto.Key) {
	backoff := time.Second
	const maxBackoff = 60 * time.Second

	for ctx.Err() == nil {
		start := time.Now()
		err := runOnce(ctx, src, cameraDir, segDurationSec, ffmpegLogLevel, credKey)
		if ctx.Err() != nil {
			return
		}

		if time.Since(start) > 60*time.Second {
			backoff = time.Second // ran healthily for a while; reset
		} else {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		log.Printf("recording: camera %s ffmpeg exited (%v), retrying in %v", src.CameraID, err, backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func runOnce(ctx context.Context, src cameraSource, cameraDir string, segDurationSec int, ffmpegLogLevel string, credKey appcrypto.Key) error {
	authedURL, err := camera.AuthenticatedURL(credKey, src.MainstreamURI, src.CredEnc, src.CredNonce)
	if err != nil {
		return err
	}

	args := []string{
		"-hide_banner",
		"-loglevel", ffmpegLogLevel,
		"-nostdin",
		"-rtsp_transport", "tcp",
		// RTSP demuxer socket I/O timeout, in microseconds (confirmed via
		// `ffmpeg -h demuxer=rtsp` against the exact build this Dockerfile
		// installs — this ffmpeg version's flag is "-timeout", not the
		// older/removed "-stimeout"). Without this, a connection that goes
		// silent without a clean TCP close/RST can leave ffmpeg blocked
		// indefinitely with no supervisor-visible exit; the restart-with-
		// backoff loop is the real resilience mechanism, this just bounds
		// how long a single hung attempt can block it.
		"-timeout", "10000000",
		"-i", authedURL,
		"-c", "copy",
		// Cheap insurance, no re-encode: some cameras only emit SPS/PPS
		// once at stream start rather than repeating them per-IDR, which
		// would otherwise make every HLS segment after the first
		// undecodable on its own (HLS requires standalone-decodable
		// segments). A harmless no-op if the camera already repeats them.
		"-bsf:v", "h264_metadata=repeat_headers=1",
		"-f", "hls",
		"-hls_time", strconv.Itoa(segDurationSec),
		"-hls_list_size", "6",
		// temp_file: ffmpeg writes "<name>.ts.tmp" and atomically renames
		// to "<name>.ts" only once fully written — this rename IS the
		// "segment finalized" signal segmentwatcher.go relies on.
		"-hls_flags", "temp_file+independent_segments",
		"-strftime", "1",
		"-strftime_mkdir", "1",
		"-hls_segment_filename", filepath.Join(cameraDir, "%Y-%m-%d", "seg_%Y%m%d_%H%M%S.ts"),
		filepath.Join(cameraDir, "live_index.m3u8"), // required output arg; never served to clients
	}

	cmd := exec.CommandContext(ctx, "ffmpeg", args...)
	// strftime() uses localtime() — force UTC so filename timestamps
	// match segmentwatcher.go's UTC parsing unambiguously, and match the
	// TIMESTAMPTZ columns they're stored into.
	cmd.Env = append(os.Environ(), "TZ=UTC")
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdout = nil
	cmd.Stderr = &ffmpegLogWriter{cameraID: src.CameraID}

	return cmd.Run()
}

// ffmpegLogWriter forwards ffmpeg's stderr line-by-line into the standard
// logger, tagged with the camera ID, without needing a separate buffering
// goroutine per worker.
type ffmpegLogWriter struct {
	cameraID string
	mu       sync.Mutex
	buf      []byte
}

func (w *ffmpegLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		log.Printf("recording: ffmpeg[%s]: %s", w.cameraID, string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}
