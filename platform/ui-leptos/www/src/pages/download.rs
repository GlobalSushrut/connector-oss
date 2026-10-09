use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[derive(Clone, PartialEq)]
enum Os { Linux, Mac, Docker }

#[component]
pub fn Download(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let releases = LocalResource::new(|| api::get_root_value("/api/v1/distribution/releases"));
    let (os, set_os) = create_signal(Os::Linux);
    let (arch, set_arch) = create_signal("amd64".to_string());
    let (dl_link, set_dl_link) = create_signal::<Option<Value>>(None);
    let (dl_loading, set_dl_loading) = create_signal(false);
    let (dl_error, set_dl_error) = create_signal(String::new());
    let (copied, set_copied) = create_signal(false);

    let request_download = move |_| {
        let os_str = match os.get() {
            Os::Linux  => "linux",
            Os::Mac    => "darwin",
            Os::Docker => "linux",
        };
        let arch_v = arch.get();
        set_dl_loading.set(true);
        set_dl_error.set(String::new());
        set_dl_link.set(None);
        spawn_local(async move {
            match api::post_root_value("/api/v1/distribution/download-link", serde_json::json!({
                "platform": os_str,
                "arch": arch_v,
                "version": "latest",
            })).await {
                Ok(v)  => { set_dl_link.set(Some(v)); }
                Err(e) => { set_dl_error.set(e.message); }
            }
            set_dl_loading.set(false);
        });
    };

    let install_cmd = move || match os.get() {
        Os::Linux  => format!(
            "curl -fsSL https://get.cnktros.com/install.sh | bash -s -- --arch {}",
            arch.get()
        ),
        Os::Mac    => format!(
            "curl -fsSL https://get.cnktros.com/install.sh | bash -s -- --os darwin --arch {}",
            arch.get()
        ),
        Os::Docker => "docker pull ghcr.io/connector-os/connector-platform:latest".to_string(),
    };

    view! {
        <div class="cn-page">
            <NavBar auth=auth set_auth=set_auth />

            // ── Hero ──────────────────────────────────────────────────────────
            <section style="padding:4rem 1.5rem 2rem;text-align:center;border-bottom:1px solid var(--cn-border)">
                <div style="display:inline-flex;align-items:center;gap:0.5rem;background:rgba(62,207,142,.1);border:1px solid rgba(62,207,142,.25);border-radius:999px;padding:0.25rem 0.85rem;margin-bottom:1.25rem">
                    <span style="width:7px;height:7px;border-radius:50%;background:var(--cn-accent);display:inline-block"></span>
                    <span style="font-size:0.75rem;font-weight:600;color:var(--cn-accent);letter-spacing:0.04em">"PILOT RELEASE — v0.1.0"</span>
                </div>
                <h1 style="font-size:2.5rem;font-weight:800;color:var(--cn-text);letter-spacing:-0.03em;margin:0 0 0.75rem">
                    "Install Connector OS"
                </h1>
                <p style="font-size:1.05rem;color:var(--cn-muted);max-width:520px;margin:0 auto 2rem">
                    "Self-hosted agent infrastructure. Runs on your machine, connects to your AI tools, reports to your portal."
                </p>
                // Platform tabs
                <div style="display:flex;gap:0.5rem;justify-content:center;flex-wrap:wrap">
                    {[("Linux", Os::Linux, "🐧"), ("macOS", Os::Mac, "🍎"), ("Docker", Os::Docker, "🐳")].into_iter().map(|(label, val, icon)| {
                        let v2 = val.clone();
                        view! {
                            <button
                                on:click=move |_| set_os.set(val.clone())
                                style=move || if os.get() == v2 {
                                    "background:rgba(62,207,142,.15);border:1px solid rgba(62,207,142,.4);color:var(--cn-accent);border-radius:10px;padding:0.5rem 1.25rem;font-size:0.875rem;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:0.4rem;transition:all .15s"
                                } else {
                                    "background:var(--cn-panel);border:1px solid var(--cn-border);color:var(--cn-muted);border-radius:10px;padding:0.5rem 1.25rem;font-size:0.875rem;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:0.4rem;transition:all .15s"
                                }
                            ><span>{icon}</span><span>{label}</span></button>
                        }
                    }).collect::<Vec<_>>()}
                </div>
                // Arch
                <div style="margin-top:0.75rem;display:flex;gap:0.4rem;justify-content:center">
                    {[("x86-64 / amd64", "amd64"), ("ARM64", "arm64")].into_iter().map(|(label, val)| {
                        let v2 = val.to_string();
                        view! {
                            <button
                                on:click=move |_| set_arch.set(val.to_string())
                                style=move || if arch.get() == v2 {
                                    "background:rgba(62,207,142,.1);border:1px solid rgba(62,207,142,.3);color:var(--cn-accent);border-radius:7px;padding:0.25rem 0.75rem;font-size:0.75rem;font-weight:600;cursor:pointer;transition:all .15s"
                                } else {
                                    "background:transparent;border:1px solid var(--cn-border);color:var(--cn-subtle);border-radius:7px;padding:0.25rem 0.75rem;font-size:0.75rem;cursor:pointer;transition:all .15s"
                                }
                            >{label}</button>
                        }
                    }).collect::<Vec<_>>()}
                </div>
            </section>

            <div style="max-width:760px;margin:0 auto;padding:2.5rem 1.5rem;display:flex;flex-direction:column;gap:1.5rem">

                // ── One-liner install ─────────────────────────────────────────
                <div class="cn-card" style="padding:1.75rem">
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
                        <span style="font-size:0.7rem;font-weight:700;letter-spacing:0.08em;color:var(--cn-accent)">"RECOMMENDED"</span>
                    </div>
                    <h2 style="font-size:1.1rem;font-weight:700;color:var(--cn-text);margin:0 0 0.5rem">"One-line install"</h2>
                    <p style="font-size:0.85rem;color:var(--cn-muted);margin:0 0 1rem">"Detects your OS and architecture, downloads the right binary, installs to "<code style="font-family:monospace;color:var(--cn-text)">/usr/local/bin</code>", writes a config template, and optionally sets up a systemd service."</p>
                    <div style="background:var(--cn-bg);border:1px solid var(--cn-border);border-radius:10px;padding:1rem 1.25rem;display:flex;align-items:center;justify-content:space-between;gap:1rem">
                        <code style="font-family:monospace;font-size:0.8rem;color:#3ecf8e;word-break:break-all;flex:1">{move || install_cmd()}</code>
                        <button
                            style="shrink:0;background:var(--cn-panel);border:1px solid var(--cn-border);color:var(--cn-muted);border-radius:6px;padding:0.3rem 0.7rem;font-size:0.72rem;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s"
                            on:click=move |_| {
                                let cmd = install_cmd();
                                let js = format!("navigator.clipboard.writeText({:?}).catch(()=>{{}})", cmd);
                                let _ = js_sys::eval(&js);
                                set_copied.set(true);
                                // reset after 2s
                                spawn_local(async move {
                                    gloo_timers::future::TimeoutFuture::new(2000).await;
                                    set_copied.set(false);
                                });
                            }
                        >{move || if copied.get() { "Copied!" } else { "Copy" }}</button>
                    </div>
                    <p style="margin-top:0.6rem;font-size:0.72rem;color:var(--cn-subtle)">
                        "Review the script before running: "
                        <a href="https://github.com/GlobalSushrut/connector-private/releases/download/v0.1.0/install.sh"
                           style="color:var(--cn-accent)" target="_blank">"view install.sh"</a>
                    </p>
                </div>

                // ── Manual tarball download ───────────────────────────────────
                <div class="cn-card" style="padding:1.75rem">
                    <h2 style="font-size:1.1rem;font-weight:700;color:var(--cn-text);margin:0 0 0.5rem">"Manual download (.tar.gz)"</h2>
                    <p style="font-size:0.85rem;color:var(--cn-muted);margin:0 0 1rem">
                        "Contains "<code style="font-family:monospace;color:var(--cn-text);font-size:0.8rem">"connector-platform"</code>
                        ", "<code style="font-family:monospace;color:var(--cn-text);font-size:0.8rem">"connectorctl"</code>
                        ", config template, and README. SHA-256 checksum included."
                    </p>
                    <button
                        class="btn-primary"
                        disabled=dl_loading
                        on:click=request_download
                    >
                        {move || if dl_loading.get() { "Generating link…" } else { "Get download link" }}
                    </button>

                    {move || if !dl_error.get().is_empty() {
                        view! {
                            <p style="margin-top:0.75rem;font-size:0.82rem;color:var(--cn-danger)">{dl_error.get()}</p>
                        }.into_any()
                    } else { view!{<span/>}.into_any() }}

                    {move || if let Some(v) = dl_link.get() {
                        let url      = v["download_url"].as_str().unwrap_or("").to_string();
                        let checksum = v["checksum_url"].as_str().unwrap_or("").to_string();
                        let version  = v["version"].as_str().unwrap_or("0.1.0").to_string();
                        let tier     = v["tier"].as_str().unwrap_or("Pilot").to_string();
                        view! {
                            <div style="margin-top:1rem;border:1px solid rgba(62,207,142,.25);background:rgba(62,207,142,.05);border-radius:10px;padding:1rem 1.25rem;display:flex;flex-direction:column;gap:0.75rem">
                                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap">
                                    <span style="color:var(--cn-accent);font-weight:700;font-size:0.85rem">"✓ Ready to download"</span>
                                    <span style="font-size:0.75rem;color:var(--cn-muted)">{format!("v{} · {}", version, tier)}</span>
                                </div>
                                <div style="display:flex;flex-wrap:wrap;gap:0.75rem">
                                    <a href=url.clone()
                                       class="btn-primary"
                                       style="font-size:0.82rem"
                                       target="_blank">"Download .tar.gz →"</a>
                                    <a href=checksum
                                       style="background:var(--cn-panel);border:1px solid var(--cn-border);color:var(--cn-muted);border-radius:8px;padding:0.45rem 1rem;font-size:0.78rem;font-weight:500;text-decoration:none"
                                       target="_blank">"SHA-256"</a>
                                </div>
                                <code style="font-family:monospace;font-size:0.7rem;color:var(--cn-subtle);word-break:break-all">{url}</code>
                            </div>
                        }.into_any()
                    } else { view!{<span/>}.into_any() }}
                </div>

                // ── After install steps ───────────────────────────────────────
                <div class="cn-card" style="padding:1.75rem">
                    <h2 style="font-size:1.1rem;font-weight:700;color:var(--cn-text);margin:0 0 1.25rem">"After install"</h2>
                    <ol style="display:flex;flex-direction:column;gap:1rem;list-style:none;padding:0;margin:0">
                        {[
                            ("Get your pilot API key",    "Log in → API Keys tab → copy your cpk_pilot_* key",    "Get API key →", "/app/api-keys"),
                            ("Add key to config",         "Edit ~/.connector/connector.toml — set license.key",   "", ""),
                            ("Start the node",            "connector-platform --config ~/.connector/connector.toml  (or: systemctl --user start connector)", "", ""),
                            ("Open dashboard",            "http://localhost:9090  — log in with your portal credentials", "", ""),
                            ("Connect your AI tool",      "Set MCP server to http://localhost:9090/api/v1/mcp in Cursor / Windsurf / Claude Desktop", "Docs →", "https://portal.cnktros.com/docs"),
                        ].into_iter().enumerate().map(|(i, (title, detail, cta, href))| view! {
                            <li style="display:flex;gap:0.875rem;align-items:flex-start">
                                <span style="flex-shrink:0;width:1.5rem;height:1.5rem;border-radius:50%;background:rgba(62,207,142,.15);border:1px solid rgba(62,207,142,.3);display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:700;color:var(--cn-accent)">{i+1}</span>
                                <div>
                                    <p style="font-size:0.875rem;font-weight:600;color:var(--cn-text);margin:0 0 0.15rem">{title}</p>
                                    <p style="font-size:0.78rem;color:var(--cn-muted);margin:0;font-family:monospace">{detail}</p>
                                    {if !cta.is_empty() {
                                        view! {
                                            <a href=href style="margin-top:0.25rem;display:inline-block;font-size:0.75rem;color:var(--cn-accent);text-decoration:none" target="_blank">{cta}</a>
                                        }.into_any()
                                    } else { view!{<span/>}.into_any() }}
                                </div>
                            </li>
                        }).collect::<Vec<_>>()}
                    </ol>
                </div>

                // ── Release history ───────────────────────────────────────────
                <div class="cn-card" style="padding:1.75rem">
                    <h2 style="font-size:1.1rem;font-weight:700;color:var(--cn-text);margin:0 0 1rem">"Releases"</h2>
                    <Suspense fallback=|| view!{ <div style="height:3rem;background:var(--cn-panel);border-radius:8px;animation:pulse 1.5s infinite"/> }>
                        {move || Suspend::new(async move {
                            match releases.await {
                                Ok(v) => {
                                    let current = v["current"].as_str().unwrap_or("0.1.0").to_string();
                                    let list = v["releases"].as_array().cloned().unwrap_or_default();
                                    view! {
                                        <div>
                                            <p style="font-size:0.8rem;color:var(--cn-muted);margin:0 0 0.75rem">
                                                "Current stable: "
                                                <span style="font-family:monospace;font-weight:700;color:var(--cn-text)">{format!("v{}", current)}</span>
                                            </p>
                                            <div style="border:1px solid var(--cn-border);border-radius:8px;overflow:hidden">
                                                {list.into_iter().map(|r| {
                                                    let ver  = r["version"].as_str().unwrap_or("—").to_string();
                                                    let date = r["date"].as_str().unwrap_or("—").to_string();
                                                    let ch   = r["channel"].as_str().unwrap_or("").to_string();
                                                    let plats = r["platforms"].as_array()
                                                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                                                        .unwrap_or_default();
                                                    let rel_url = r["release_url"].as_str().unwrap_or("").to_string();
                                                                    let ch2 = ch.clone();
                                                    view! {
                                                        <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:0.75rem;padding:0.75rem 1rem;border-bottom:1px solid var(--cn-border)">
                                                            <div style="display:flex;align-items:center;gap:0.75rem">
                                                                <span style="font-family:monospace;font-weight:700;color:var(--cn-text);font-size:0.875rem">{format!("v{}", ver)}</span>
                                                                <span style=if ch == "stable" {
                                                                    "background:rgba(62,207,142,.12);border:1px solid rgba(62,207,142,.25);color:var(--cn-accent);border-radius:999px;padding:0.15rem 0.5rem;font-size:0.7rem;font-weight:700"
                                                                } else {
                                                                    "background:var(--cn-panel);border:1px solid var(--cn-border);color:var(--cn-muted);border-radius:999px;padding:0.15rem 0.5rem;font-size:0.7rem;font-weight:600"
                                                                }>{ch2}</span>
                                                            </div>
                                                            <span style="font-size:0.75rem;color:var(--cn-muted)">{date}</span>
                                                            <span style="font-size:0.72rem;color:var(--cn-subtle)">{plats}</span>
                                                            {if !rel_url.is_empty() {
                                                                view! {
                                                                    <a href=rel_url style="font-size:0.75rem;color:var(--cn-accent);text-decoration:none" target="_blank">"GitHub →"</a>
                                                                }.into_any()
                                                            } else { view!{<span/>}.into_any() }}
                                                        </div>
                                                    }
                                                }).collect::<Vec<_>>()}
                                            </div>
                                        </div>
                                    }.into_any()
                                }
                                Err(_) => view! {
                                    <p style="font-size:0.82rem;color:var(--cn-muted)">"Release list unavailable."</p>
                                }.into_any(),
                            }
                        })}
                    </Suspense>
                </div>

                // ── System requirements ───────────────────────────────────────
                <div class="cn-card" style="padding:1.75rem">
                    <h2 style="font-size:1.1rem;font-weight:700;color:var(--cn-text);margin:0 0 1rem">"System requirements"</h2>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0.75rem">
                        {[
                            ("OS", "Linux (glibc ≥2.17) or macOS 12+"),
                            ("CPU", "1 core min · 4 recommended"),
                            ("RAM", "512 MB min · 2 GB recommended"),
                            ("Disk", "1 GB min · 10 GB recommended"),
                            ("Network", "Outbound HTTPS to portal.cnktros.com"),
                            ("License", "Pilot API key (cpk_pilot_*)"),
                        ].into_iter().map(|(k, v)| view! {
                            <div style="background:var(--cn-panel);border:1px solid var(--cn-border);border-radius:8px;padding:0.75rem">
                                <p style="font-size:0.7rem;font-weight:700;color:var(--cn-subtle);letter-spacing:0.05em;margin:0 0 0.25rem">{k}</p>
                                <p style="font-size:0.8rem;color:var(--cn-muted);margin:0">{v}</p>
                            </div>
                        }).collect::<Vec<_>>()}
                    </div>
                </div>

            </div>
        </div>
    }
}
