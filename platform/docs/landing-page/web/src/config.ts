const rawYt = import.meta.env.VITE_YOUTUBE_VIDEO_ID as string | undefined
export const youtubeVideoId =
  rawYt?.trim() && rawYt !== 'REPLACE_ME' ? rawYt.trim() : ''

export const youtubeEmbedSrc = youtubeVideoId
  ? `https://www.youtube-nocookie.com/embed/${youtubeVideoId}?rel=0`
  : ''

/** Control-plane URLs (set in Vercel env for production). */
export const portalBaseUrl =
  (import.meta.env.VITE_PORTAL_BASE_URL as string | undefined)?.replace(/\/$/, '') ||
  'https://portal.cnktros.com'
export const playgroundBaseUrl =
  (import.meta.env.VITE_PLAYGROUND_BASE_URL as string | undefined)?.replace(/\/$/, '') ||
  'https://try.cnktros.com'
export const apiBaseUrl =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ||
  'https://api.cnktros.com'

export const portalSignupUrl = `${portalBaseUrl}/signup`
export const portalLoginUrl = `${portalBaseUrl}/login`
export const playgroundUrl = `${playgroundBaseUrl}/trial`
