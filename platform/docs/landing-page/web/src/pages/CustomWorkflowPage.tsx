import { Navigate } from 'react-router-dom'

/** Regulated-industry packages are not a product today. Keep the URL from selling them. */
export function CustomWorkflowPage() {
  return <Navigate to="/" replace />
}
