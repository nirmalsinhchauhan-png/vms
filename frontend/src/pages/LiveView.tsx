import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import Hls from 'hls.js'
import { apiJSON } from '../lib/api'

interface Camera {
  id: string
  name: string
  status: string
}

const LIVE_BASE = import.meta.env.VITE_LIVE_BASE_URL

export default function LiveView() {
  const { id } = useParams<{ id: string }>()
  const videoRef = useRef<HTMLVideoElement>(null)
  const [camera, setCamera] = useState<Camera | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    apiJSON<Camera>(`/cameras/${id}`)
      .then(setCamera)
      .catch((err) => setError(err instanceof Error ? err.message : 'Could not load camera'))
  }, [id])

  useEffect(() => {
    const video = videoRef.current
    if (!video || !id) return

    const src = `${LIVE_BASE}/api/stream.m3u8?src=${encodeURIComponent(id)}`
    setError(null)

    // go2rtc's live HLS output (substream) — a separate pipeline from
    // recorded playback, never gated behind the HLS token auth that guards
    // /recordings/, since go2rtc itself has no auth of its own and is only
    // ever reached through nginx's /live/ location within the compose network.
    if (Hls.isSupported()) {
      const hls = new Hls({ lowLatencyMode: true })
      hls.on(Hls.Events.ERROR, (_evt, data) => {
        if (data.fatal) {
          setError(`Playback error: ${data.details}`)
        }
      })
      hls.loadSource(src)
      hls.attachMedia(video)
      return () => hls.destroy()
    }

    if (video.canPlayType('application/vnd.apple.mpegurl')) {
      video.src = src
      return
    }

    setError('This browser cannot play HLS video.')
  }, [id])

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: '2rem', maxWidth: 960 }}>
      <p>
        <Link to="/cameras">&larr; Back to cameras</Link>
      </p>
      <h1>{camera?.name ?? 'Live view'}</h1>
      {camera && <p>Status: {camera.status}</p>}
      {error && <p style={{ color: 'crimson' }}>{error}</p>}
      <video
        ref={videoRef}
        controls
        autoPlay
        muted
        playsInline
        style={{ width: '100%', maxWidth: 960, backgroundColor: '#000' }}
      />
    </main>
  )
}
