use leptos::prelude::*;
use leptos_router::components::A;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[component]
pub fn Landing(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (_, set_auth) = create_signal(AuthState::default());

    view! {
        <div class="cn-page">
            <NavBar auth=auth set_auth=set_auth />

            // ── Hero ───────────────────────────────────────────────────────
            <section style="border-bottom:1px solid var(--cn-border)">
                <div class="cn-inner" style="padding-top:5rem;padding-bottom:5rem">
                    <div style="display:grid;align-items:center;gap:3rem;grid-template-columns:1fr 1fr">
                        // Left: headline + CTAs
                        <div style="display:flex;flex-direction:column;gap:1.5rem">
                            // Beta pill
                            <div style="display:inline-flex;align-items:center;gap:0.5rem;border:1px solid rgba(255,176,32,.3);background:rgba(255,176,32,.08);border-radius:9999px;padding:0.3rem 0.85rem;font-size:0.72rem;font-weight:600;color:var(--cn-warn);width:fit-content">
                                <span style="width:6px;height:6px;border-radius:50%;background:var(--cn-warn);flex-shrink:0"></span>
                                "Controlled Beta — selected teams only"
                            </div>

                            <div style="display:flex;flex-direction:column;gap:0.75rem">
                                <h1 style="font-size:clamp(2rem,4vw,3.25rem);font-weight:700;letter-spacing:-0.03em;line-height:1.1;color:var(--cn-text);margin:0">
                                    "Self-hosted AI governance. Hosted control plane."
                                </h1>
                                <p style="font-size:1.05rem;line-height:1.65;color:var(--cn-muted);margin:0;max-width:32rem">
                                    "Get a license key, download the binary, run a governed node, and route your AI tools through DevGuard. No cloud lock-in."
                                </p>
                            </div>

                            <div style="display:flex;flex-wrap:wrap;align-items:center;gap:0.75rem">
                                <A href="/signup" attr:class="btn-primary">"Join Beta"</A>
                                <A href="/login"  attr:class="btn-secondary">"Sign in"</A>
                                <a href="https://connector-playground.fly.dev" target="_blank"
                                   style="font-size:0.85rem;color:var(--cn-muted);text-decoration:none;border:1px solid var(--cn-border);border-radius:8px;padding:0.45rem 1rem;transition:color .15s,border-color .15s"
                                   onmouseover="this.style.color='var(--cn-accent)';this.style.borderColor='rgba(62,207,142,.4)'"
                                   onmouseout="this.style.color='var(--cn-muted)';this.style.borderColor='var(--cn-border)'"
                                >"Try playground →"</a>
                            </div>

                            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:0.75rem;padding-top:0.5rem">
                                {[
                                    ("Hosted portal", "Signup, billing, API keys, profile, entitlement."),
                                    ("Local dashboard", "Token-only. Agents, trust, memory, runtime."),
                                    ("Self-hosted", "Your infra, your data. Binary runs on-prem."),
                                ].into_iter().map(|(title, desc)| view!{
                                    <div style="background:var(--cn-panel);border:1px solid var(--cn-border);border-radius:12px;padding:1rem">
                                        <p class="cn-label">{title}</p>
                                        <p style="font-size:0.8rem;color:var(--cn-muted);margin:0.5rem 0 0">{desc}</p>
                                    </div>
                                }).collect::<Vec<_>>()}
                            </div>
                        </div>

                        // Right: topology card
                        <div style="background:var(--cn-panel);border:1px solid var(--cn-border);border-radius:20px;padding:1.5rem;box-shadow:0 0 60px rgba(62,207,142,.06)">
                            <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--cn-border);padding-bottom:1rem;margin-bottom:1.25rem">
                                <div>
                                    <p style="font-size:0.85rem;font-weight:600;color:var(--cn-text);margin:0">"Connector topology"</p>
                                    <p style="font-size:0.72rem;color:var(--cn-muted);margin:0.2rem 0 0">"Control plane split"</p>
                                </div>
                                <span class="badge-green">"Healthy"</span>
                            </div>
                            <div style="display:flex;flex-direction:column;gap:0.75rem">
                                {[
                                    ("CONTROL SERVER", "Portal + admin + billing + entitlement", "Hosted account system with customer and admin surfaces.", false),
                                    ("NODE SERVER",    "Dashboard + API + operations",            "Local runtime secured through your API key.", false),
                                    ("OPERATOR FLOW",  "Sign up → generate key → open dashboard", "No portal-style auth on the node UI.",                    true),
                                ].into_iter().map(|(label, title, desc, accent)| {
                                    let bg = if accent { "background:var(--cn-accent-dim);border-color:rgba(62,207,142,.2)" } else { "background:var(--cn-bg-elevated);border-color:var(--cn-border)" };
                                    let label_color = if accent { "color:var(--cn-accent)" } else { "color:var(--cn-muted)" };
                                    let title_color = if accent { "color:var(--cn-text)" } else { "color:var(--cn-text)" };
                                    view!{
                                        <div style=format!("border-radius:12px;border:1px solid;padding:1rem;{bg}")>
                                            <p style=format!("font-size:0.68rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin:0;{label_color}")>{label}</p>
                                            <p style=format!("font-size:0.85rem;font-weight:600;margin:0.5rem 0 0.25rem;{title_color}")>{title}</p>
                                            <p style="font-size:0.78rem;color:var(--cn-muted);margin:0">{desc}</p>
                                        </div>
                                    }
                                }).collect::<Vec<_>>()}
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            // ── How it works ───────────────────────────────────────────────
            <section class="cn-inner" style="padding-top:4rem;padding-bottom:4rem">
                <p class="cn-label" style="text-align:center;margin-bottom:2rem">"How it works"</p>
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem">
                    {[
                        ("01", "Request beta access", "Submit your details via the join beta form. We review and send your license key within 48 hours."),
                        ("02", "Download the binary", "Log in, go to Download, pick your OS and architecture, and get the signed binary tied to your license."),
                        ("03", "Run your node",       "Boot the platform daemon, open the local dashboard, connect your AI tools through DevGuard."),
                    ].into_iter().map(|(n, title, desc)| view!{
                        <div class="card" style="position:relative">
                            <span style="font-size:0.7rem;font-weight:700;color:var(--cn-accent);font-family:'JetBrains Mono',monospace;letter-spacing:.05em">{n}</span>
                            <h3 style="font-size:0.95rem;font-weight:600;color:var(--cn-text);margin:0.75rem 0 0.5rem">{title}</h3>
                            <p style="font-size:0.82rem;color:var(--cn-muted);line-height:1.6;margin:0">{desc}</p>
                        </div>
                    }).collect::<Vec<_>>()}
                </div>
            </section>

            // ── Footer ─────────────────────────────────────────────────────
            <footer style="border-top:1px solid var(--cn-border);padding:1.5rem 0">
                <div class="cn-inner" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.75rem">
                    <p style="font-size:0.78rem;color:var(--cn-muted);margin:0">"© 2025 Connector. Controlled beta."</p>
                    <div style="display:flex;gap:1.25rem">
                        <a href="https://connector-playground.fly.dev" target="_blank" style="font-size:0.78rem;color:var(--cn-muted);text-decoration:none">"Playground"</a>
                        <A href="/login"  attr:style="font-size:0.78rem;color:var(--cn-muted);text-decoration:none">"Sign in"</A>
                        <A href="/signup" attr:style="font-size:0.78rem;color:var(--cn-muted);text-decoration:none">"Join Beta"</A>
                    </div>
                </div>
            </footer>
        </div>
    }
}
