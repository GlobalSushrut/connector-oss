import { useEffect } from 'react'

interface MetaOptions {
  title: string
  description: string
  canonical?: string
}

export function useMeta({ title, description, canonical }: MetaOptions) {
  useEffect(() => {
    document.title = title

    let desc = document.querySelector('meta[name="description"]')
    if (!desc) {
      desc = document.createElement('meta')
      desc.setAttribute('name', 'description')
      document.head.appendChild(desc)
    }
    desc.setAttribute('content', description)

    let canon = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null
    if (canonical) {
      if (!canon) {
        canon = document.createElement('link')
        canon.setAttribute('rel', 'canonical')
        document.head.appendChild(canon)
      }
      canon.setAttribute('href', canonical)
    }

    let ogTitle = document.querySelector('meta[property="og:title"]')
    if (!ogTitle) {
      ogTitle = document.createElement('meta')
      ogTitle.setAttribute('property', 'og:title')
      document.head.appendChild(ogTitle)
    }
    ogTitle.setAttribute('content', title)

    let ogDesc = document.querySelector('meta[property="og:description"]')
    if (!ogDesc) {
      ogDesc = document.createElement('meta')
      ogDesc.setAttribute('property', 'og:description')
      document.head.appendChild(ogDesc)
    }
    ogDesc.setAttribute('content', description)

    if (canonical) {
      let ogUrl = document.querySelector('meta[property="og:url"]')
      if (!ogUrl) {
        ogUrl = document.createElement('meta')
        ogUrl.setAttribute('property', 'og:url')
        document.head.appendChild(ogUrl)
      }
      ogUrl.setAttribute('content', canonical)
    }

    return () => {
      document.title = 'Connector · AI Agent Governance Infrastructure'
    }
  }, [title, description, canonical])
}
