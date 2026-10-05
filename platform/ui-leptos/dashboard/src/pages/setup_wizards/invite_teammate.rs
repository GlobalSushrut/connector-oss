//! Invite-teammate wizard — `/setup/invite`.
//!
//! Backend-aligned flow (there is no `/invites` route):
//!
//! 1. **Details** — name + work email (+ optional temp password).
//! 2. **Access**  — platform role (`viewer` / `operator` / `developer` / `admin`).
//! 3. **Create**  — `POST /auth/signup` then optional `POST /auth/users/role`,
//!                  then `POST /setup/complete` with `invite_teammate`.
//!
//! Shows the issued API key / credentials so the admin can hand them off
//! when SMTP magic-links are not available.

use leptos::prelude::*;
use leptos_router::components::A;
use serde::{Deserialize, Serialize};
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::install_card::PlaygroundDeflect;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};

const WIZARD_ID: &str = "invite-teammate";
const SERVER_WIZARD_ID: &str = "invite_teammate";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteState {
    full_name: String,
    email: String,
    password: String,
    role: String,
    sent: bool,
    user_id: String,
    api_key: String,
    assigned_role: String,
    error: String,
    note: String,
}

impl Default for InviteState {
    fn default() -> Self {
        Self {
            full_name: String::new(),
            email: String::new(),
            password: String::new(),
            role: "operator".into(),
            sent: false,
            user_id: String::new(),
            api_key: String::new(),
            assigned_role: String::new(),
            error: String::new(),
            note: String::new(),
        }
    }
}

fn soft_error(v: &serde_json::Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Some(
            v.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Request failed")
                .into(),
        );
    }
    if let Some(status) = v.get("status").and_then(|s| s.as_u64()) {
        if status >= 400 {
            return Some(
                v.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Request failed")
                    .into(),
            );
        }
    }
    v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string())
}

fn gen_temp_password() -> String {
    // Readable temp password that satisfies prod rules (upper/lower/digit/special).
    let n = js_sys::Date::now() as u64;
    format!("Tmp-{n:x}Aa!")
}

#[component]
pub fn InviteTeammateWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("Invite a teammate");
    let _ = auth;

    view! {
        <PlaygroundDeflect>
            <div class="w-full">
                <div class="mx-auto w-full max-w-3xl px-4 py-6 sm:px-6">
                    <div class="mb-4">
                        <h1 class="text-lg font-semibold text-zinc-100">"Invite a teammate"</h1>
                        <p class="mt-1 text-xs text-zinc-500">
                            "Creates a local identity via POST /auth/signup, then sets role with POST /auth/users/role."
                        </p>
                    </div>
                    <InviteInner />
                </div>
            </div>
        </PlaygroundDeflect>
    }
}

#[component]
fn InviteInner() -> impl IntoView {
    let steps = vec![
        WizardStep::new("details", "Their details")
            .with_subtitle("Name, work email, and a temporary password."),
        WizardStep::new("access", "Access level")
            .with_subtitle("Platform roles from GET /auth/rbac/roles."),
        WizardStep::new("send", "Create account")
            .with_subtitle("Signup + role assignment — share credentials securely.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<InviteState>(WIZARD_ID);
    let (busy, set_busy) = signal(false);

    let on_finish = Callback::new({
        let controller = controller;
        move |()| {
            if busy.get_untracked() || state.get_untracked().sent {
                if state.get_untracked().sent {
                    controller.next(true);
                }
                return;
            }
            let mut s = state.get();
            if s.email.trim().is_empty() || !s.email.contains('@') {
                set_state.update(|st| st.error = "Valid work email is required.".into());
                return;
            }
            if s.full_name.trim().is_empty() {
                set_state.update(|st| st.error = "Full name is required.".into());
                return;
            }
            if s.password.trim().len() < 6 {
                s.password = gen_temp_password();
                set_state.update(|st| st.password = s.password.clone());
            }
            set_busy.set(true);
            set_state.update(|st| {
                st.error.clear();
                st.note.clear();
            });
            spawn_local(async move {
                let signup_body = json!({
                    "email": s.email.trim(),
                    "password": s.password,
                    "name": s.full_name.trim(),
                });
                match api::post_value("/auth/signup", signup_body).await {
                    Ok(v) => {
                        if let Some(err) = soft_error(&v) {
                            set_state.update(|st| {
                                st.sent = false;
                                st.error = err;
                            });
                            set_busy.set(false);
                            return;
                        }
                        let user_id = v
                            .get("user_id")
                            .and_then(|x| x.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let api_key = v
                            .get("api_key")
                            .and_then(|x| x.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let mut assigned = "viewer".to_string();
                        let mut note = String::new();

                        if !user_id.is_empty() && s.role != "viewer" {
                            match api::post_value(
                                "/auth/users/role",
                                json!({ "user_id": user_id, "role": s.role }),
                            )
                            .await
                            {
                                Ok(rv) => {
                                    if let Some(err) = soft_error(&rv) {
                                        note = format!(
                                            "Account created, but role was not elevated ({err}). SuperAdmin required for POST /auth/users/role."
                                        );
                                    } else {
                                        assigned = rv
                                            .get("new_role")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or(&s.role)
                                            .to_string();
                                    }
                                }
                                Err(e) => {
                                    note = format!(
                                        "Account created, but role elevation failed: {}.",
                                        e.message
                                    );
                                }
                            }
                        } else {
                            assigned = s.role.clone();
                        }

                        let _ = api::post_value(
                            "/setup/complete",
                            json!({ "wizard_id": SERVER_WIZARD_ID }),
                        )
                        .await;

                        set_state.update(|st| {
                            st.sent = true;
                            st.user_id = user_id;
                            st.api_key = api_key;
                            st.assigned_role = assigned;
                            st.note = note;
                            st.error.clear();
                        });
                    }
                    Err(e) => {
                        set_state.update(|st| {
                            st.sent = false;
                            st.error = e.message;
                        });
                    }
                }
                set_busy.set(false);
            });
        }
    });

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <DetailsStep state=state set_state=set_state /> }.into_any(),
            1 => view! { <AccessStep state=state set_state=set_state /> }.into_any(),
            2 => view! { <ReviewStep state=state busy=busy /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    view! {
        <WizardShell
            controller=controller
            steps=steps
            step_view=step_view
            on_finish=on_finish
            defer_complete=true
            on_cancel=Callback::new(|()| {
                if let Some(win) = web_sys::window() {
                    let _ = win.location().set_href("/setup");
                }
            })
        />
        <ExistingUsers />
        <p class="mt-3 text-[11px] text-zinc-600">
            "Manage roles later via POST /auth/users/role. Directory: "
            <A href="/setup" attr:class="text-zinc-400 hover:text-zinc-200">"SETUP"</A>"."
        </p>
    }
}

#[component]
fn ExistingUsers() -> impl IntoView {
    let users = LocalResource::new(|| api::get_value("/auth/users"));
    view! {
        <section class="mt-6 rounded-xl border border-zinc-800/60 bg-zinc-900/30 p-4">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Current operators"</p>
            <p class="mt-0.5 mb-2 font-mono text-[10px] text-zinc-600">"GET /auth/users"</p>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    match users.await {
                        Ok(v) => {
                            if let Some(err) = soft_error(&v) {
                                return view! { <p class="text-xs text-amber-400">{err}</p> }.into_any();
                            }
                            let list = v
                                .get("users")
                                .and_then(|a| a.as_array())
                                .cloned()
                                .unwrap_or_default();
                            if list.is_empty() {
                                view! { <p class="text-xs text-zinc-600">"No users yet."</p> }.into_any()
                            } else {
                                view! {
                                    <ul class="max-h-40 space-y-1 overflow-y-auto">
                                        {list.into_iter().take(20).map(|u| {
                                            let email = u.get("email").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let role = u.get("role").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let name = u.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            view! {
                                                <li class="flex items-center justify-between gap-2 border-b border-zinc-800/40 py-1 text-xs">
                                                    <span class="truncate text-zinc-200">{if name.is_empty() { email.clone() } else { format!("{name} · {email}") }}</span>
                                                    <span class="shrink-0 font-mono text-[10px] text-zinc-500">{role}</span>
                                                </li>
                                            }
                                        }).collect_view()}
                                    </ul>
                                }.into_any()
                            }
                        }
                        Err(e) => view! { <p class="text-xs text-amber-400">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn DetailsStep(
    state: ReadSignal<InviteState>,
    set_state: WriteSignal<InviteState>,
) -> impl IntoView {
    view! {
        <div class="space-y-4">
            <label class="block">
                <span class="mb-1 block text-xs uppercase tracking-wider text-zinc-500">"Full name"</span>
                <input
                    type="text"
                    autocomplete="name"
                    aria-label="Teammate full name"
                    class="w-full max-w-md rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2 text-sm text-zinc-100 focus:border-indigo-500/60 focus:outline-none"
                    prop:value=move || state.get().full_name
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.full_name = v);
                    }
                />
            </label>
            <label class="block">
                <span class="mb-1 block text-xs uppercase tracking-wider text-zinc-500">"Work email"</span>
                <input
                    type="email"
                    autocomplete="email"
                    aria-label="Teammate email address"
                    placeholder="alex@yourcompany.com"
                    class="w-full max-w-md rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-indigo-500/60 focus:outline-none"
                    prop:value=move || state.get().email
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.email = v);
                    }
                />
            </label>
            <label class="block">
                <span class="mb-1 block text-xs uppercase tracking-wider text-zinc-500">"Temporary password"</span>
                <div class="flex max-w-md gap-2">
                    <input
                        type="text"
                        autocomplete="new-password"
                        aria-label="Temporary password"
                        placeholder="auto-generated on Finish if blank"
                        class="w-full rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-600 focus:border-indigo-500/60 focus:outline-none"
                        prop:value=move || state.get().password
                        on:input=move |ev| {
                            let v = event_target_value(&ev);
                            set_state.update(|s| s.password = v);
                        }
                    />
                    <button
                        type="button"
                        class="shrink-0 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300 hover:bg-zinc-900"
                        on:click=move |_| set_state.update(|s| s.password = gen_temp_password())
                    >"Generate"</button>
                </div>
                <p class="mt-1 text-[11px] text-zinc-600">
                    "POST /auth/signup requires email + password + name. Share the password out-of-band — this node does not send magic-link invites."
                </p>
            </label>
        </div>
    }
}

#[component]
fn AccessStep(
    state: ReadSignal<InviteState>,
    set_state: WriteSignal<InviteState>,
) -> impl IntoView {
    let roles = [
        ("viewer", "Viewer", "Read-only — dashboards, logs, reports."),
        ("operator", "Operator", "Day-to-day ops — workflows, approvals, budgets."),
        ("developer", "Developer", "Build + debug surfaces; limited admin."),
        ("admin", "Admin", "Full control — license, settings, billing, identity."),
    ];

    view! {
        <div class="space-y-4">
            <div class="grid grid-cols-1 gap-2" role="radiogroup" aria-label="Teammate role">
                {roles.iter().map(|(slug, label, desc)| {
                    let slug_owned = slug.to_string();
                    let selected = {
                        let s = slug_owned.clone();
                        Memo::new(move |_| state.get().role == s)
                    };
                    let slug_click = slug_owned.clone();
                    view! {
                        <button
                            type="button"
                            role="radio"
                            aria-checked=move || selected.get().to_string()
                            class=move || if selected.get() {
                                "rounded-lg border border-indigo-500/50 bg-indigo-500/10 px-3 py-2 text-left"
                            } else {
                                "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-3 py-2 text-left hover:border-zinc-700/80"
                            }
                            on:click=move |_| {
                                let v = slug_click.clone();
                                set_state.update(|s| s.role = v);
                            }
                        >
                            <p class="text-sm font-medium text-zinc-200">{*label}</p>
                            <p class="mt-0.5 text-xs text-zinc-400">{*desc}</p>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
            <p class="text-[11px] text-zinc-600">
                "Role elevation uses POST /auth/users/role and requires SuperAdmin. Signup alone leaves the account at the server default (often viewer)."
            </p>
        </div>
    }
}

#[component]
fn ReviewStep(state: ReadSignal<InviteState>, busy: ReadSignal<bool>) -> impl IntoView {
    view! {
        <div class="space-y-4">
            <div class="space-y-2 rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-4">
                <p class="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">"Summary"</p>
                <dl class="grid grid-cols-[8rem_1fr] gap-y-1 text-sm">
                    <dt class="text-zinc-500">"Name"</dt>
                    <dd class="text-zinc-100">{move || state.get().full_name}</dd>
                    <dt class="text-zinc-500">"Email"</dt>
                    <dd class="break-all font-mono text-zinc-100">{move || state.get().email}</dd>
                    <dt class="text-zinc-500">"Role"</dt>
                    <dd class="capitalize text-zinc-100">{move || state.get().role}</dd>
                    <dt class="text-zinc-500">"Password"</dt>
                    <dd class="break-all font-mono text-xs text-zinc-300">
                        {move || {
                            let p = state.get().password;
                            if p.is_empty() { "(auto on Finish)".into() } else { p }
                        }}
                    </dd>
                </dl>
            </div>
            <Show when=move || busy.get()>
                <p class="text-xs text-zinc-400">"Creating account…"</p>
            </Show>
            {move || {
                let s = state.get();
                if !s.error.is_empty() && !s.sent {
                    view! {
                        <p class="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">{s.error.clone()}</p>
                    }.into_any()
                } else if s.sent {
                    view! {
                        <div role="status" aria-live="polite" class="space-y-2 rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
                            <p class="text-sm font-semibold text-emerald-300">"Account created"</p>
                            <dl class="grid grid-cols-[7rem_1fr] gap-y-1 text-xs">
                                <dt class="text-zinc-500">"user_id"</dt>
                                <dd class="break-all font-mono text-zinc-200">{s.user_id.clone()}</dd>
                                <dt class="text-zinc-500">"role"</dt>
                                <dd class="font-mono text-zinc-200">{s.assigned_role.clone()}</dd>
                                <dt class="text-zinc-500">"password"</dt>
                                <dd class="break-all font-mono text-zinc-200">{s.password.clone()}</dd>
                            </dl>
                            {(!s.api_key.is_empty()).then(|| view! {
                                <div>
                                    <p class="text-[11px] text-zinc-500">"API key (shown once — copy now):"</p>
                                    <code class="mt-1 block break-all rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200">
                                        {s.api_key.clone()}
                                    </code>
                                </div>
                            })}
                            {(!s.note.is_empty()).then(|| view! {
                                <p class="text-[11px] text-amber-300">{s.note.clone()}</p>
                            })}
                            <p class="text-[11px] text-zinc-500">
                                "They sign in at /login with email + password, or use the API key as Bearer."
                            </p>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <p class="text-xs text-zinc-500">
                            "Finish runs POST /auth/signup → POST /auth/users/role → POST /setup/complete. After success, Finish again to close the wizard."
                        </p>
                    }.into_any()
                }
            }}
        </div>
    }
}
