import { BrowserRouter, Navigate, Routes, Route } from 'react-router-dom'
import { HomePage } from './pages/HomePage'
import { AboutOsPage } from './pages/AboutOsPage'
import { GetStartedPage } from './pages/GetStartedPage'
import { DevelopersPage } from './pages/DevelopersPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/about-os" element={<AboutOsPage />} />
        <Route path="/get-started" element={<GetStartedPage />} />
        <Route path="/developers" element={<DevelopersPage />} />
        <Route path="/products/:slug" element={<Navigate to="/#outcomes" replace />} />
        <Route path="/use-cases" element={<Navigate to="/#outcomes" replace />} />
        <Route path="/custom-workflows" element={<Navigate to="/#future" replace />} />
        <Route path="/about-us" element={<Navigate to="/#maintainer" replace />} />
        <Route path="/blog" element={<Navigate to="/" replace />} />
        <Route path="/blog/:slug" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
