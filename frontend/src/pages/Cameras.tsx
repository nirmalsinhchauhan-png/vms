import { useEffect, useState, type FormEvent } from 'react'
import { apiJSON } from '../lib/api'
import { useAuth } from '../context/useAuth'

interface Site {
  id: string
  name: string
}

interface Camera {
  id: string
  site_id: string
  name: string
  manufacturer: string
  model: string
  ip_address: string
  mainstream_uri: string
  substream_uri?: string
  status: string
  ptz_capable: boolean
  created_at: string
}

interface CameraDetails {
  manufacturer: string
  model: string
  mainstream_uri: string
  substream_uri: string
}

interface DiscoveredDevice {
  endpoint_ref: string
  xaddrs: string[]
  remote_addr: string
}

const emptyForm = {
  site_id: '',
  name: '',
  manufacturer: '',
  model: '',
  ip_address: '',
  mainstream_uri: '',
  substream_uri: '',
  username: '',
  password: '',
}

export default function Cameras() {
  const { user, logout } = useAuth()
  const [sites, setSites] = useState<Site[]>([])
  const [cameras, setCameras] = useState<Camera[]>([])
  const [form, setForm] = useState(emptyForm)
  const [probing, setProbing] = useState(false)
  const [discovering, setDiscovering] = useState(false)
  const [discovered, setDiscovered] = useState<DiscoveredDevice[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const canWrite = user?.role === 'admin' || user?.role === 'operator'

  async function loadAll() {
    const [siteList, cameraList] = await Promise.all([
      apiJSON<Site[]>('/sites'),
      apiJSON<Camera[]>('/cameras'),
    ])
    setSites(siteList)
    setCameras(cameraList)
    if (siteList.length > 0 && !form.site_id) {
      setForm((f) => ({ ...f, site_id: siteList[0].id }))
    }
  }

  useEffect(() => {
    loadAll().catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function updateField<K extends keyof typeof emptyForm>(key: K, value: (typeof emptyForm)[K]) {
    setForm((f) => ({ ...f, [key]: value }))
  }

  async function handleProbe() {
    setError(null)
    setNotice(null)
    if (!form.ip_address || !form.username || !form.password) {
      setError('IP address, username, and password are required to probe a camera')
      return
    }
    setProbing(true)
    try {
      const details = await apiJSON<CameraDetails>('/cameras/probe', {
        method: 'POST',
        body: JSON.stringify({
          ip_address: form.ip_address,
          username: form.username,
          password: form.password,
        }),
      })
      setForm((f) => ({
        ...f,
        manufacturer: details.manufacturer,
        model: details.model,
        mainstream_uri: details.mainstream_uri,
        substream_uri: details.substream_uri,
      }))
      setNotice('Camera details filled in from ONVIF — review before saving.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Probe failed')
    } finally {
      setProbing(false)
    }
  }

  async function handleDiscover() {
    setError(null)
    setNotice(null)
    setDiscovering(true)
    try {
      const { devices } = await apiJSON<{ devices: DiscoveredDevice[] }>('/cameras/discover', {
        method: 'POST',
      })
      setDiscovered(devices)
      if (devices.length === 0) {
        setNotice(
          'No cameras found. This is expected behind Docker/WSL2 networking — use the manual IP + credentials fields above instead.',
        )
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Discovery failed')
    } finally {
      setDiscovering(false)
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setNotice(null)
    try {
      await apiJSON('/cameras', { method: 'POST', body: JSON.stringify(form) })
      setForm((f) => ({ ...emptyForm, site_id: f.site_id }))
      setNotice('Camera added.')
      await loadAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add camera')
    }
  }

  async function handleDelete(id: string) {
    setError(null)
    try {
      await apiJSON(`/cameras/${id}`, { method: 'DELETE' })
      await loadAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove camera')
    }
  }

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: '2rem', maxWidth: 720 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h1>Cameras</h1>
        <div>
          <span style={{ marginRight: '1rem' }}>
            {user?.full_name} ({user?.role})
          </span>
          <button type="button" onClick={() => logout()}>
            Sign out
          </button>
        </div>
      </div>

      {error && <p style={{ color: 'crimson' }}>{error}</p>}
      {notice && <p style={{ color: 'seagreen' }}>{notice}</p>}

      <section>
        <h2>Registered cameras</h2>
        {cameras.length === 0 ? (
          <p>No cameras yet.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left' }}>Name</th>
                <th style={{ textAlign: 'left' }}>IP</th>
                <th style={{ textAlign: 'left' }}>Status</th>
                {canWrite && <th />}
              </tr>
            </thead>
            <tbody>
              {cameras.map((cam) => (
                <tr key={cam.id}>
                  <td>{cam.name}</td>
                  <td>{cam.ip_address}</td>
                  <td>{cam.status}</td>
                  {canWrite && (
                    <td>
                      <button type="button" onClick={() => handleDelete(cam.id)}>
                        Remove
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canWrite && (
        <section>
          <h2>Add a camera</h2>
          <div style={{ marginBottom: '0.75rem' }}>
            <button type="button" onClick={handleDiscover} disabled={discovering}>
              {discovering ? 'Scanning…' : 'Discover cameras on the network'}
            </button>
            {discovered && discovered.length > 0 && (
              <ul>
                {discovered.map((d) => (
                  <li key={d.endpoint_ref || d.remote_addr}>
                    {d.remote_addr} — {d.xaddrs.join(', ')}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <form
            onSubmit={handleCreate}
            style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}
          >
            <label>
              Site
              <select
                value={form.site_id}
                onChange={(e) => updateField('site_id', e.target.value)}
                required
                style={{ display: 'block', width: '100%' }}
              >
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Name
              <input
                value={form.name}
                onChange={(e) => updateField('name', e.target.value)}
                required
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <label>
              IP address
              <input
                value={form.ip_address}
                onChange={(e) => updateField('ip_address', e.target.value)}
                required
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <label>
              ONVIF username
              <input
                value={form.username}
                onChange={(e) => updateField('username', e.target.value)}
                required
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <label>
              ONVIF / camera password
              <input
                type="password"
                value={form.password}
                onChange={(e) => updateField('password', e.target.value)}
                required
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <button type="button" onClick={handleProbe} disabled={probing}>
              {probing ? 'Probing…' : 'Probe camera (fills in fields below)'}
            </button>
            <label>
              Manufacturer
              <input
                value={form.manufacturer}
                onChange={(e) => updateField('manufacturer', e.target.value)}
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <label>
              Model
              <input
                value={form.model}
                onChange={(e) => updateField('model', e.target.value)}
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <label>
              Mainstream URI (recording)
              <input
                value={form.mainstream_uri}
                onChange={(e) => updateField('mainstream_uri', e.target.value)}
                required
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <label>
              Substream URI (live view)
              <input
                value={form.substream_uri}
                onChange={(e) => updateField('substream_uri', e.target.value)}
                style={{ display: 'block', width: '100%' }}
              />
            </label>
            <button type="submit">Add camera</button>
          </form>
        </section>
      )}
    </main>
  )
}
