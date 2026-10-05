/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_YOUTUBE_VIDEO_ID: string
  /** POST target for pilot form (default /api/submit-pilot) */
  readonly VITE_PILOT_SUBMIT_URL: string
  readonly VITE_PORTAL_BASE_URL: string
  readonly VITE_PLAYGROUND_BASE_URL: string
  readonly VITE_API_BASE_URL: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
