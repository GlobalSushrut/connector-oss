import { youtubeEmbedSrc } from '../config'

export function VideoSection() {
  return (
    <section id="video" className="section section--bordered">
      <div className="section__inner">
        <h2 className="section__title">See Connector in action</h2>
        <p className="section__lead">
          Short walkthrough: isolation, policy at runtime, and receipts you can
          hand to an auditor.
        </p>
        {youtubeEmbedSrc ? (
          <div className="video-frame">
            <iframe
              title="Connector overview video"
              src={youtubeEmbedSrc}
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
              allowFullScreen
              loading="lazy"
              referrerPolicy="strict-origin-when-cross-origin"
            />
          </div>
        ) : (
          <div className="video-placeholder card">
            <p>
              Set <code>VITE_YOUTUBE_VIDEO_ID</code> in <code>.env</code> (just
              the ID, not the full URL).
            </p>
          </div>
        )}
        <ul className="checklist">
          <li>Isolation: agents scoped so data and roles do not blend</li>
          <li>Governance: budget and policy enforced before tools run</li>
          <li>Verification: receipts and traceability, not a log dump</li>
        </ul>
      </div>
    </section>
  )
}
