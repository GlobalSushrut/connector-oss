//! Shared **HTML report shell** (print-ready) and **PDF** rendering for Connector ecosystem exports.
//!
//! Used by WitnessCtl session exports and TraceTramp compliance exports. PDF path tries
//! headless Chrome/Chromium then `wkhtmltopdf`, matching production deployments on RHEL/Ubuntu.

use std::io;
use std::path::Path;
use std::process::Command;

use thiserror::Error;
use tracing::{debug, warn};

/// Wrap an **HTML fragment** (e.g. from Markdown) in a full document with print CSS.
///
/// Operators can open the returned string as `text/html` and use **Print → Save as PDF**
/// in any browser without server-side renderers.
///
/// `html_body` is appended verbatim (must be trusted/safe HTML); only `title` and
/// `footer_line` are HTML-escaped.
pub fn html_report_document(html_body: &str, title: &str, footer_line: &str) -> String {
    let escaped_title = html_escape(title);
    let escaped_footer = html_escape(footer_line);
    const HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>"#;
    const MID: &str = r#"</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 11pt;
      line-height: 1.6;
      color: #1a1a2e;
      max-width: 900px;
      margin: 0 auto;
      padding: 32px 40px;
    }
    h1 {
      font-size: 20pt;
      color: #0d1b2a;
      border-bottom: 2px solid #1a1a2e;
      padding-bottom: 8px;
      margin-bottom: 24px;
    }
    h2 {
      font-size: 14pt;
      color: #1a1a2e;
      border-bottom: 1px solid #ccc;
      padding-bottom: 4px;
      margin-top: 32px;
      margin-bottom: 12px;
    }
    h3 { font-size: 12pt; color: #333; margin-top: 20px; }
    p { margin: 8px 0; }
    strong { color: #0d1b2a; }
    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 9.5pt;
      background: #f4f4f8;
      border: 1px solid #ddd;
      border-radius: 3px;
      padding: 1px 5px;
    }
    pre { background: #f4f4f8; border: 1px solid #ddd; border-radius: 4px; padding: 12px; overflow-x: auto; }
    pre code { background: none; border: none; padding: 0; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
      font-size: 9.5pt;
    }
    th {
      background: #1a1a2e;
      color: #fff;
      text-align: left;
      padding: 6px 10px;
      font-weight: 600;
    }
    td { padding: 5px 10px; border-bottom: 1px solid #e0e0e0; }
    tr:nth-child(even) td { background: #f8f8fc; }
    ul, ol { margin: 8px 0; padding-left: 24px; }
    li { margin: 4px 0; }
    em { color: #555; }
    blockquote {
      border-left: 4px solid #1a1a2e;
      margin: 12px 0;
      padding: 4px 16px;
      color: #555;
    }
    .footer {
      margin-top: 48px;
      border-top: 1px solid #ccc;
      padding-top: 12px;
      font-size: 9pt;
      color: #888;
    }
    @media print {
      body { padding: 20px; }
      h1, h2, h3 { page-break-after: avoid; }
      table { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
"#;
    const TAIL: &str = r#"
<div class="footer">"#;
    const END: &str = r#"</div>
</body>
</html>"#;
    let mut out = String::with_capacity(HEAD.len() + escaped_title.len() + MID.len() + html_body.len() + TAIL.len() + escaped_footer.len() + END.len());
    out.push_str(HEAD);
    out.push_str(&escaped_title);
    out.push_str(MID);
    out.push_str(html_body);
    out.push_str(TAIL);
    out.push_str(&escaped_footer);
    out.push_str(END);
    out
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[derive(Debug, Error)]
pub enum RenderPdfError {
    #[error("write temp html: {0}")]
    Io(#[from] io::Error),
    #[error("PDF rendering failed: no PDF renderer available. Install google-chrome, chromium, or wkhtmltopdf. {0}")]
    NoRenderer(String),
}

/// Render a **full HTML document** (including `<!DOCTYPE`) to PDF bytes.
pub fn render_pdf(html_document: &str) -> Result<Vec<u8>, RenderPdfError> {
    let dir = std::env::temp_dir();
    let nonce = uuid::Uuid::new_v4().to_string();
    let html_path = dir.join(format!("connector-report-{}.html", nonce));
    let pdf_path = dir.join(format!("connector-report-{}.pdf", nonce));

    std::fs::write(&html_path, html_document.as_bytes())?;

    let result = render_pdf_inner(&html_path, &pdf_path);

    let _ = std::fs::remove_file(&html_path);
    let _ = std::fs::remove_file(&pdf_path);

    result
}

fn render_pdf_inner(html_path: &Path, pdf_path: &Path) -> Result<Vec<u8>, RenderPdfError> {
    let html_uri = format!("file://{}", html_path.display());

    let chrome_binaries = [
        "google-chrome-stable",
        "google-chrome",
        "chromium-browser",
        "chromium",
    ];
    let chrome_headless_flags: &[&[&str]] = &[&["--headless=new"], &["--headless"]];

    'chrome: for chrome in &chrome_binaries {
        for headless_flag in chrome_headless_flags {
            let mut args: Vec<&str> = headless_flag.to_vec();
            args.extend_from_slice(&[
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-software-rasterizer",
                "--run-all-compositor-stages-before-draw",
            ]);
            let print_arg = format!("--print-to-pdf={}", pdf_path.display());
            args.push(&print_arg);
            args.push(&html_uri);

            let out = Command::new(chrome)
                .args(&args)
                .stderr(std::process::Stdio::null())
                .output();

            match out {
                Ok(o) if o.status.success() && pdf_path.exists() => {
                    return std::fs::read(pdf_path).map_err(RenderPdfError::from);
                }
                Ok(o) if o.status.success() => {
                    debug!(binary = %chrome, ?headless_flag, "chrome exited 0 but no pdf");
                }
                Ok(o) => {
                    debug!(binary = %chrome, ?headless_flag, status = %o.status, "chrome print failed");
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue 'chrome,
                Err(e) => {
                    warn!(binary = %chrome, "chrome spawn: {}", e);
                    continue 'chrome;
                }
            }
        }
    }

    let html_path_str = html_path.display().to_string();
    let pdf_path_str = pdf_path.display().to_string();
    match Command::new("wkhtmltopdf")
        .args(["--quiet", "--disable-javascript", &html_path_str, &pdf_path_str])
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() && pdf_path.exists() => std::fs::read(pdf_path).map_err(RenderPdfError::from),
        Ok(o) => {
            debug!(status = %o.status, "wkhtmltopdf failed or produced no file");
            Err(RenderPdfError::NoRenderer(
                "wkhtmltopdf did not produce output.".into(),
            ))
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            warn!("wkhtmltopdf spawn: {}", e);
            Err(RenderPdfError::NoRenderer(e.to_string()))
        }
        _ => Err(RenderPdfError::NoRenderer(
            "wkhtmltopdf not installed.".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_wrap_contains_title_and_body() {
        let doc = html_report_document("<p>Hi</p>", "T", "foot");
        assert!(doc.contains("<title>T</title>"));
        assert!(doc.contains("<p>Hi</p>"));
        assert!(doc.contains("foot"));
        assert!(doc.contains("@media print"));
    }

    #[test]
    fn html_escape_amp() {
        let doc = html_report_document("", "A & B", "x");
        assert!(doc.contains("A &amp; B"));
    }
}
