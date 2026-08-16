import { type ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { useAuth } from './context/useAuth'
import Login from './pages/Login'
import Cameras from './pages/Cameras'
import LiveView from './pages/LiveView'

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  if (loading)
    return <p style={{ padding: '2rem', fontFamily: 'system-ui, sans-serif' }}>Loading…</p>
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/cameras"
            element={
              <ProtectedRoute>
                <Cameras />
              </ProtectedRoute>
            }
          />
          <Route
            path="/cameras/:id/watch"
            element={
              <ProtectedRoute>
                <LiveView />
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<Navigate to="/cameras" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
