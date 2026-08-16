package main

import (
	"errors"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siliconsignals/vms/backend/internal/auth"
	"github.com/siliconsignals/vms/backend/internal/recording"
)

// registerRecordingRoutes wires the minimal recorded-playback API: mint a
// short-lived signed token for /recordings/ access, list segments in a time
// range, and toggle a camera's recording schedule. Stitching an arbitrary
// time range's segments into one continuous playlist is deliberately out
// of scope — each segment gets its own trivial one-entry .m3u8 (written by
// internal/recording's SegmentWatcher), and that's the whole playback
// surface this sprint ships.
func registerRecordingRoutes(router fiber.Router, dbPool *pgxpool.Pool, issuer *auth.JWTIssuer, hlsSecret []byte, hlsTTL time.Duration, recMgr *recording.Manager) {
	authed := auth.RequireAuth(issuer)
	writeOnly := auth.RequireRole("admin", "operator")

	rec := router.Group("/cameras/:id/recordings", authed)
	rec.Get("/session", recordingSessionHandler(dbPool, hlsSecret, hlsTTL))
	rec.Get("/segments", listRecordingSegmentsHandler(dbPool))
	rec.Patch("/schedule", writeOnly, updateRecordingScheduleHandler(dbPool, recMgr))
}

func recordingSessionHandler(dbPool *pgxpool.Pool, hlsSecret []byte, ttl time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		camID := c.Params("id")
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)

		var exists bool
		err := dbPool.QueryRow(c.Context(),
			`SELECT true FROM cameras WHERE id = $1 AND organization_id = $2`, camID, orgID,
		).Scan(&exists)
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "camera not found"})
		}
		if err != nil {
			log.Printf("recordings: session lookup: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		token, err := recording.MintSegmentToken(hlsSecret, camID, ttl)
		if err != nil {
			log.Printf("recordings: mint token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		return c.JSON(fiber.Map{
			"token":          token,
			"expires_in_sec": int(ttl.Seconds()),
			"base_path":      "/recordings/" + camID + "/",
		})
	}
}

type recordingSegmentResponse struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int       `json:"duration_ms"`
	SizeBytes  int64     `json:"size_bytes"`
	HasMotion  bool      `json:"has_motion"`
}

func listRecordingSegmentsHandler(dbPool *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		camID := c.Params("id")
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)

		from, err := time.Parse(time.RFC3339, c.Query("from"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "from must be an RFC3339 timestamp"})
		}
		to, err := time.Parse(time.RFC3339, c.Query("to"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "to must be an RFC3339 timestamp"})
		}
		if !to.After(from) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "to must be after from"})
		}
		if to.Sub(from) > 7*24*time.Hour {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "range cannot exceed 7 days"})
		}

		rows, err := dbPool.Query(c.Context(), `
			SELECT rs.id, rs.file_path, rs.started_at, rs.duration_ms, rs.size_bytes, rs.has_motion
			FROM recording_segments rs
			JOIN cameras c ON c.id = rs.camera_id
			WHERE rs.camera_id = $1 AND c.organization_id = $2
			  AND rs.started_at >= $3 AND rs.started_at < $4
			ORDER BY rs.started_at ASC
			LIMIT 2000
		`, camID, orgID, from, to)
		if err != nil {
			log.Printf("recordings: list segments: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}
		defer rows.Close()

		out := []recordingSegmentResponse{}
		for rows.Next() {
			var id, filePath string
			var startedAt time.Time
			var durationMs int
			var sizeBytes int64
			var hasMotion bool
			if err := rows.Scan(&id, &filePath, &startedAt, &durationMs, &sizeBytes, &hasMotion); err != nil {
				log.Printf("recordings: scan segment: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}
			// file_path is stored relative to RECORDING_STORAGE_PATH, e.g.
			// "<camera_id>/2026-07-22/seg_....ts" — exactly what nginx's
			// `alias /data/recordings/` needs appended after /recordings/.
			// The client plays the .m3u8 sibling, not the raw .ts.
			playlistPath := trimTSExt(filePath) + ".m3u8"
			out = append(out, recordingSegmentResponse{
				ID:         id,
				URL:        "/recordings/" + playlistPath,
				StartedAt:  startedAt,
				DurationMs: durationMs,
				SizeBytes:  sizeBytes,
				HasMotion:  hasMotion,
			})
		}
		return c.JSON(out)
	}
}

func trimTSExt(p string) string {
	if len(p) > 3 && p[len(p)-3:] == ".ts" {
		return p[:len(p)-3]
	}
	return p
}

type recordingScheduleRequest struct {
	Mode          string `json:"mode"`
	RetentionDays int    `json:"retention_days"`
}

func updateRecordingScheduleHandler(dbPool *pgxpool.Pool, recMgr *recording.Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		camID := c.Params("id")
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)

		var req recordingScheduleRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		switch req.Mode {
		case "continuous", "motion", "scheduled", "disabled":
		default:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "mode must be one of continuous, motion, scheduled, disabled"})
		}
		if req.RetentionDays <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "retention_days must be positive"})
		}

		tag, err := dbPool.Exec(c.Context(), `
			UPDATE recording_schedules SET mode = $1, retention_days = $2
			WHERE camera_id = $3 AND EXISTS (
				SELECT 1 FROM cameras WHERE id = $3 AND organization_id = $4
			)
		`, req.Mode, req.RetentionDays, camID, orgID)
		if err != nil {
			log.Printf("recordings: update schedule: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}
		if tag.RowsAffected() == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "camera not found"})
		}

		recMgr.TriggerReconcile()
		return c.JSON(fiber.Map{"mode": req.Mode, "retention_days": req.RetentionDays})
	}
}
