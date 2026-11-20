import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { startGuard } from './security/guard'
import './style.css'

startGuard() // 운영 빌드에서만 동작한다
createRoot(document.getElementById('app')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
