package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siliconsignals/vms/backend/internal/auth"
	"github.com/siliconsignals/vms/backend/internal/camera"
	"github.com/siliconsignals/vms/backend/internal/config"
	appcrypto "github.com/siliconsignals/vms/backend/internal/crypto"
	"github.com/siliconsignals/vms/backend/internal/go2rtc"
	"github.com/siliconsignals/vms/backend/internal/onvif"
	"github.com/siliconsignals/vms/backend/internal/recording"
)

// registerCameraRoutes wires camera CRUD plus ONVIF probe/discover, gated
// behind RequireAuth (all roles) and RequireRole("admin","operator") for
// anything that writes, matching the seeded role permissions.
func registerCameraRoutes(router fiber.Router, dbPool *pgxpool.Pool, issuer *auth.JWTIssuer, go2rtcClient *go2rtc.Client, credKey appcrypto.Key, cfg config.Config, recMgr *recording.Manager) {
	authed := auth.RequireAuth(issuer)
	writeOnly := auth.RequireRole("admin", "operator")

	cameras := router.Group("/cameras", authed)
	cameras.Get("/", listCamerasHandler(dbPool))
	cameras.Get("/:id", getCameraHandler(dbPool))
	cameras.Post("/", writeOnly, createCameraHandler(dbPool, go2rtcClient, credKey, cfg, recMgr))
	cameras.Patch("/:id", writeOnly, updateCameraHandler(dbPool, go2rtcClient, credKey, recMgr))
	cameras.Delete("/:id", writeOnly, deleteCameraHandler(dbPool, go2rtcClient, cfg, recMgr))
	cameras.Post("/probe", writeOnly, probeCameraHandler(cfg))
	cameras.Post("/discover", writeOnly, discoverCamerasHandler(cfg))

	router.Get("/sites", authed, listSitesHandler(dbPool))
}

type cameraResponse struct {
	ID            string    `json:"id"`
	SiteID        string    `json:"site_id"`
	Name          string    `json:"name"`
	Manufacturer  string    `json:"manufacturer"`
	Model         string    `json:"model"`
	IPAddress     string    `json:"ip_address"`
	MainstreamURI string    `json:"mainstream_uri"`
	SubstreamURI  *string   `json:"substream_uri,omitempty"`
	Status        string    `json:"status"`
	PTZCapable    bool      `json:"ptz_capable"`
	CreatedAt     time.Time `json:"created_at"`
}

const cameraSelectColumns = `id, site_id, name, manufacturer, model, ip_address::text, mainstream_uri, substream_uri, status, ptz_capable, created_at`

func scanCamera(row interface{ Scan(...any) error }) (cameraResponse, error) {
	var cr cameraResponse
	err := row.Scan(&cr.ID, &cr.SiteID, &cr.Name, &cr.Manufacturer, &cr.Model, &cr.IPAddress,
		&cr.MainstreamURI, &cr.SubstreamURI, &cr.Status, &cr.PTZCapable, &cr.CreatedAt)
	return cr, err
}

func listCamerasHandler(dbPool *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)
		rows, err := dbPool.Query(c.Context(), `SELECT `+cameraSelectColumns+` FROM cameras WHERE organization_id = $1 ORDER BY name`, orgID)
		if err != nil {
			log.Printf("camera: list query: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}
		defer rows.Close()

		out := []cameraResponse{}
		for rows.Next() {
			cr, err := scanCamera(rows)
			if err != nil {
				log.Printf("camera: list scan: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}
			out = append(out, cr)
		}
		return c.JSON(out)
	}
}

func getCameraHandler(dbPool *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)
		row := dbPool.QueryRow(c.Context(), `SELECT `+cameraSelectColumns+` FROM cameras WHERE id = $1 AND organization_id = $2`, c.Params("id"), orgID)
		cr, err := scanCamera(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "camera not found"})
		}
		if err != nil {
			log.Printf("camera: get query: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}
		return c.JSON(cr)
	}
}

type cameraWriteRequest struct {
	SiteID        string `json:"site_id"`
	Name          string `json:"name"`
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	IPAddress     string `json:"ip_address"`
	MainstreamURI string `json:"mainstream_uri"`
	SubstreamURI  string `json:"substream_uri"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

func (r cameraWriteRequest) validate() error {
	if r.SiteID == "" || r.Name == "" || r.IPAddress == "" || r.MainstreamURI == "" || r.Username == "" || r.Password == "" {
		return errors.New("site_id, name, ip_address, mainstream_uri, username, and password are required")
	}
	return nil
}

// liveStreamURI is what go2rtc registers: substream when the camera has
// one, otherwise mainstream — go2rtc is the live-view pipeline only, never
// the recording path, per the architecture's mainstream/substream split.
func (r cameraWriteRequest) liveStreamURI() string {
	if r.SubstreamURI != "" {
		return r.SubstreamURI
	}
	return r.MainstreamURI
}

func createCameraHandler(dbPool *pgxpool.Pool, go2rtcClient *go2rtc.Client, credKey appcrypto.Key, cfg config.Config, recMgr *recording.Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req cameraWriteRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if err := req.validate(); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)

		ciphertext, nonce, err := camera.Encrypt(credKey, req.Username, req.Password)
		if err != nil {
			log.Printf("camera: encrypt credentials: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		var substream any
		if req.SubstreamURI != "" {
			substream = req.SubstreamURI
		}

		var id string
		err = dbPool.QueryRow(c.Context(), `
			INSERT INTO cameras (organization_id, site_id, name, manufacturer, model, ip_address, mainstream_uri, substream_uri, credential_enc, credential_nonce)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id
		`, orgID, req.SiteID, req.Name, req.Manufacturer, req.Model, req.IPAddress, req.MainstreamURI, substream, ciphertext, nonce).Scan(&id)
		if err != nil {
			log.Printf("camera: insert: %v", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "could not create camera — check site_id and ip_address are valid"})
		}

		// go2rtc registration is best-effort: a temporarily-unreachable
		// go2rtc shouldn't block camera creation. The row is persisted
		// either way; status reflects whether registration succeeded.
		// The live URI carries real credentials injected via net/url (not
		// string-templated) — go2rtc cannot authenticate to the camera's
		// RTSP server otherwise, regardless of what's stored for the camera.
		status := "online"
		liveURI, err := camera.InjectAuth(req.liveStreamURI(), req.Username, req.Password)
		if err != nil {
			log.Printf("camera: build authenticated live URI for %s: %v", id, err)
			status = "error"
		} else if err := go2rtcClient.RegisterStream(c.Context(), id, liveURI); err != nil {
			log.Printf("camera: go2rtc register (best-effort) for %s: %v", id, err)
			status = "error"
		}
		if _, err := dbPool.Exec(c.Context(), `UPDATE cameras SET status = $1 WHERE id = $2`, status, id); err != nil {
			log.Printf("camera: set initial status: %v", err)
		}

		// Recording is on by default — matches ordinary VMS expectations,
		// and an admin can flip mode/retention via the schedule endpoint
		// afterward. Best-effort: a failure here shouldn't fail camera
		// creation, same rationale as the go2rtc registration above.
		if _, err := dbPool.Exec(c.Context(),
			`INSERT INTO recording_schedules (camera_id, mode, retention_days) VALUES ($1, 'continuous', $2)`,
			id, cfg.RecordingRetentionDays,
		); err != nil {
			log.Printf("camera: create default recording schedule for %s: %v", id, err)
		} else {
			recMgr.TriggerReconcile()
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id, "status": status})
	}
}

func updateCameraHandler(dbPool *pgxpool.Pool, go2rtcClient *go2rtc.Client, credKey appcrypto.Key, recMgr *recording.Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)

		var req cameraWriteRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if err := req.validate(); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		ciphertext, nonce, err := camera.Encrypt(credKey, req.Username, req.Password)
		if err != nil {
			log.Printf("camera: encrypt credentials: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		var substream any
		if req.SubstreamURI != "" {
			substream = req.SubstreamURI
		}

		tag, err := dbPool.Exec(c.Context(), `
			UPDATE cameras SET site_id=$1, name=$2, manufacturer=$3, model=$4, ip_address=$5,
				mainstream_uri=$6, substream_uri=$7, credential_enc=$8, credential_nonce=$9
			WHERE id = $10 AND organization_id = $11
		`, req.SiteID, req.Name, req.Manufacturer, req.Model, req.IPAddress, req.MainstreamURI, substream, ciphertext, nonce, id, orgID)
		if err != nil {
			log.Printf("camera: update: %v", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "could not update camera"})
		}
		if tag.RowsAffected() == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "camera not found"})
		}

		liveURI, err := camera.InjectAuth(req.liveStreamURI(), req.Username, req.Password)
		if err != nil {
			log.Printf("camera: build authenticated live URI for %s: %v", id, err)
		} else if err := go2rtcClient.RegisterStream(c.Context(), id, liveURI); err != nil {
			log.Printf("camera: go2rtc re-register (best-effort) for %s: %v", id, err)
		}

		// mainstream_uri and/or credentials may have changed — the recording
		// worker needs restarting against the new config, not left running
		// against stale credentials/URI until it happens to crash on its own.
		recMgr.TriggerReconcile()

		return c.JSON(fiber.Map{"id": id})
	}
}

func deleteCameraHandler(dbPool *pgxpool.Pool, go2rtcClient *go2rtc.Client, cfg config.Config, recMgr *recording.Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)

		tag, err := dbPool.Exec(c.Context(), `DELETE FROM cameras WHERE id = $1 AND organization_id = $2`, id, orgID)
		if err != nil {
			log.Printf("camera: delete: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}
		if tag.RowsAffected() == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "camera not found"})
		}

		if err := go2rtcClient.RemoveStream(c.Context(), id); err != nil {
			log.Printf("camera: go2rtc remove (best-effort) for %s: %v", id, err)
		}

		// cameras -> recording_segments cascades away the DB *rows* on
		// delete but leaves the *files* on disk with no record of them at
		// all — the retention sweep can't find orphans it has no row for.
		// Best-effort, same rationale as the go2rtc removal above.
		recMgr.TriggerReconcile()
		if err := os.RemoveAll(filepath.Join(cfg.RecordingStoragePath, id)); err != nil {
			log.Printf("camera: remove recording directory for %s (best-effort): %v", id, err)
		}

		return c.SendStatus(fiber.StatusNoContent)
	}
}

type probeCameraRequest struct {
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func probeCameraHandler(cfg config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req probeCameraRequest
		if err := c.BodyParser(&req); err != nil || req.IPAddress == "" || req.Username == "" || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ip_address, username, and password are required"})
		}

		// Covers the full GetDeviceInformation -> GetCapabilities ->
		// GetProfiles -> GetStreamUri x2 sequence, not just one call.
		ctx, cancel := context.WithTimeout(c.Context(), cfg.ONVIFSOAPTimeout*5)
		defer cancel()

		details, err := onvif.FetchCameraDetails(ctx, req.IPAddress, req.Port, req.Username, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, onvif.ErrUnauthorized):
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "camera rejected the given credentials"})
			case errors.Is(err, onvif.ErrDeviceUnreachable):
				return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "camera did not respond — check the IP address and that it's reachable from the backend"})
			case errors.Is(err, onvif.ErrNoVideoProfiles):
				return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "camera exposed no usable video profile"})
			default:
				log.Printf("camera: onvif probe: %v", err)
				return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "could not read camera details"})
			}
		}

		return c.JSON(details)
	}
}

func discoverCamerasHandler(cfg config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !cfg.ONVIFDiscoveryEnabled {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "ONVIF discovery is disabled on this deployment"})
		}

		devices, err := onvif.Discover(c.Context(), cfg.ONVIFDiscoveryTimeout)
		if err != nil {
			log.Printf("camera: onvif discover: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "discovery failed to start"})
		}
		// An empty result is the normal outcome (no devices replied within
		// the timeout) — not an error. Very likely on a Dockerized/WSL2 dev
		// deployment; see the Sprint 2 plan's networking caveat.
		return c.JSON(fiber.Map{"devices": devices})
	}
}

type siteResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func listSitesHandler(dbPool *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, _ := c.Locals(auth.LocalOrganizationID).(string)
		rows, err := dbPool.Query(c.Context(), `SELECT id, name FROM sites WHERE organization_id = $1 ORDER BY name`, orgID)
		if err != nil {
			log.Printf("sites: list query: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}
		defer rows.Close()

		out := []siteResponse{}
		for rows.Next() {
			var s siteResponse
			if err := rows.Scan(&s.ID, &s.Name); err != nil {
				log.Printf("sites: list scan: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}
			out = append(out, s)
		}
		return c.JSON(out)
	}
}

// reconcileGo2RTCStreams re-registers every camera's live stream with
// go2rtc at startup. Postgres is the source of truth for cameras, not
// go2rtc's own config file, so this makes stream registration resilient to
// go2rtc restarts/config resets rather than depending on go2rtc's own
// file-persistence behavior (which has a real quirk: PUT /api/streams
// tries to write the change back into its YAML config, which fails if
// that file is read-only — see docker-compose.yml's go2rtc volume comment).
func reconcileGo2RTCStreams(ctx context.Context, dbPool *pgxpool.Pool, go2rtcClient *go2rtc.Client, credKey appcrypto.Key) {
	rows, err := dbPool.Query(ctx, `SELECT id, mainstream_uri, substream_uri, credential_enc, credential_nonce FROM cameras`)
	if err != nil {
		log.Printf("go2rtc reconcile: query cameras: %v", err)
		return
	}
	defer rows.Close()

	registered, failed := 0, 0
	for rows.Next() {
		var id, mainstream string
		var substream *string
		var credEnc, credNonce []byte
		if err := rows.Scan(&id, &mainstream, &substream, &credEnc, &credNonce); err != nil {
			log.Printf("go2rtc reconcile: scan: %v", err)
			continue
		}
		streamURI := mainstream
		if substream != nil && *substream != "" {
			streamURI = *substream
		}
		liveURI, err := camera.AuthenticatedURL(credKey, streamURI, credEnc, credNonce)
		if err != nil {
			log.Printf("go2rtc reconcile: build authenticated URL for %s: %v", id, err)
			failed++
			continue
		}
		if err := go2rtcClient.RegisterStream(ctx, id, liveURI); err != nil {
			log.Printf("go2rtc reconcile: register %s: %v", id, err)
			failed++
			continue
		}
		registered++
	}
	log.Printf("go2rtc reconcile: registered %d camera stream(s), %d failed", registered, failed)
}
