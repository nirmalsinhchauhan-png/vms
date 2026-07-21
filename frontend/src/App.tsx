import { useEffect, useState } from 'react'
import Hls from 'hls.js'

type ApiStatus = 'checking' | 'ok' | 'unreachable'

function App() {
  const [apiStatus, setApiStatus] = useState<ApiStatus>('checking')

  useEffect(() => {
    const controller = new AbortController()

    fetch(`${import.meta.env.VITE_API_BASE_URL}/v1/ping`, { signal: controller.signal })
      .then((res) => setApiStatus(res.ok ? 'ok' : 'unreachable'))
      .catch(() => setApiStatus('unreachable'))

    return () => controller.abort()
  }, [])

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: '2rem' }}>
      <h1>{import.meta.env.VITE_APP_TITLE || 'VMS Platform'}</h1>
      <p>Backend API: {apiStatus}</p>
      <p>hls.js MSE support: {Hls.isSupported() ? 'yes' : 'no'}</p>
    </main>
  )
}

export default App
