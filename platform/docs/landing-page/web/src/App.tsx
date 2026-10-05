import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { HomePage } from './pages/HomePage'
import { AboutOsPage } from './pages/AboutOsPage'
import { UseCasesPage } from './pages/UseCasesPage'
import { ProductPage } from './pages/ProductPage'
import { CustomWorkflowPage } from './pages/CustomWorkflowPage'
import { AboutUsPage } from './pages/AboutUsPage'
import { BlogListPage } from './pages/BlogListPage'
import { BlogPostPage } from './pages/BlogPostPage'
import { GetStartedPage } from './pages/GetStartedPage'
import { DevelopersPage } from './pages/DevelopersPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/about-os" element={<AboutOsPage />} />
        <Route path="/use-cases" element={<UseCasesPage />} />
        <Route path="/products/:slug" element={<ProductPage />} />
        <Route path="/custom-workflows" element={<CustomWorkflowPage />} />
        <Route path="/about-us" element={<AboutUsPage />} />
        <Route path="/blog" element={<BlogListPage />} />
        <Route path="/blog/:slug" element={<BlogPostPage />} />
        <Route path="/get-started" element={<GetStartedPage />} />
        <Route path="/developers" element={<DevelopersPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
