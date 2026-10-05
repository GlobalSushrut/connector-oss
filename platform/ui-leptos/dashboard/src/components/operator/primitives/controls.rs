use leptos::ev::MouseEvent;
use leptos::prelude::*;
use std::sync::Arc;

pub type OpClick = Arc<dyn Fn(MouseEvent) + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum OpButtonVariant {
    #[default]
    Primary,
    Secondary,
    Ghost,
    Danger,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum OpButtonSize {
    Sm,
    #[default]
    Md,
    Lg,
}

#[component]
pub fn OpButton(
    #[prop(into)] label: String,
    #[prop(default = OpButtonVariant::Primary)] variant: OpButtonVariant,
    #[prop(default = OpButtonSize::Md)] size: OpButtonSize,
    #[prop(default = false)] loading: bool,
    #[prop(optional)] on_click: Option<OpClick>,
    #[prop(optional)] disabled: Option<bool>,
) -> impl IntoView {
    let variant_class = match variant {
        OpButtonVariant::Primary => "btn-primary",
        OpButtonVariant::Secondary => "btn-secondary",
        OpButtonVariant::Ghost => "btn-ghost",
        OpButtonVariant::Danger => "btn-danger",
    };
    let size_class = match size {
        OpButtonSize::Sm => "h-8 px-3 text-xs",
        OpButtonSize::Md => "h-9 px-4 text-sm",
        OpButtonSize::Lg => "h-10 px-5 text-sm",
    };
    let is_disabled = move || disabled.unwrap_or(false) || loading;
    view! {
        <button
            type="button"
            class=format!("inline-flex items-center justify-center gap-2 font-semibold transition-all duration-150 disabled:opacity-50 disabled:pointer-events-none disabled:transform-none {variant_class} {size_class}")
            disabled=is_disabled
            aria-busy=move || loading
            on:click=move |ev| {
                ev.stop_propagation();
                if !is_disabled() {
                    if let Some(ref h) = on_click {
                        h(ev);
                    }
                }
            }
        >
            {loading.then(|| view! {
                <span class="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" aria-hidden="true"></span>
            })}
            {label}
        </button>
    }
}

#[component]
pub fn OpIconButton(
    #[prop(into)] label: String,
    children: Children,
    #[prop(optional)] on_click: Option<OpClick>,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded-lg text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
            aria-label=label
            on:click=move |ev| {
                if let Some(ref h) = on_click {
                    h(ev);
                }
            }
        >
            {children()}
        </button>
    }
}

#[component]
pub fn OpKbd(#[prop(into)] keys: String) -> impl IntoView {
    view! {
        <kbd class="hidden sm:inline-flex items-center rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
            {keys}
        </kbd>
    }
}

#[component]
pub fn OpSearchField(
    value: ReadSignal<String>,
    set_value: WriteSignal<String>,
    #[prop(default = "Search…")] placeholder: &'static str,
) -> impl IntoView {
    view! {
        <div class="relative">
            <input
                type="search"
                class="w-full h-9 rounded-lg border border-zinc-800 bg-zinc-900/60 pl-9 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
                placeholder=placeholder
                prop:value=move || value.get()
                on:input=move |ev| {
                    set_value.set(event_target_value(&ev));
                }
            />
            <span class="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600 text-xs" aria-hidden="true">"⌕"</span>
        </div>
    }
}

#[component]
pub fn OpTextField(
    value: ReadSignal<String>,
    set_value: WriteSignal<String>,
    #[prop(into, optional, default = "Label".to_string())] label: String,
    #[prop(into, optional, default = String::new())] placeholder: String,
    #[prop(default = false)] password: bool,
) -> impl IntoView {
    let input_type = if password { "password" } else { "text" };
    let ph = placeholder.clone();
    view! {
        <label class="flex flex-col gap-1.5">
            <span class="text-xs font-medium text-zinc-400">{label}</span>
            <input
                type=input_type
                class="h-9 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
                placeholder=ph
                prop:value=move || value.get()
                on:input=move |ev| set_value.set(event_target_value(&ev))
            />
        </label>
    }
}

#[component]
pub fn OpSelect(
    value: ReadSignal<String>,
    set_value: WriteSignal<String>,
    #[prop(into, optional, default = "Select".to_string())] label: String,
    options: Vec<(String, String)>,
) -> impl IntoView {
    view! {
        <label class="flex flex-col gap-1.5">
            <span class="text-xs font-medium text-zinc-400">{label}</span>
            <select
                class="h-9 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
                on:change=move |ev| set_value.set(event_target_value(&ev))
            >
                {options.into_iter().map(|(val, text)| {
                    let val_cmp = val.clone();
                    view! {
                        <option value=val.clone() selected=move || value.get() == val_cmp>{text}</option>
                    }
                }).collect_view()}
            </select>
        </label>
    }
}

#[component]
pub fn OpSwitch(
    checked: ReadSignal<bool>,
    set_checked: WriteSignal<bool>,
    #[prop(into)] label: String,
) -> impl IntoView {
    view! {
        <label class="inline-flex cursor-pointer items-center gap-2">
            <button
                type="button"
                role="switch"
                aria-checked=move || checked.get()
                class=move || {
                    if checked.get() {
                        "relative h-5 w-9 rounded-full bg-emerald-500 transition-colors"
                    } else {
                        "relative h-5 w-9 rounded-full bg-zinc-700 transition-colors"
                    }
                }
                on:click=move |_| set_checked.update(|v| *v = !*v)
            >
                <span
                    class=move || {
                        if checked.get() {
                            "absolute top-0.5 left-4 h-4 w-4 rounded-full bg-white shadow transition-all"
                        } else {
                            "absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white shadow transition-all"
                        }
                    }
                ></span>
            </button>
            <span class="text-sm text-zinc-300">{label}</span>
        </label>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpViewMode {
    Grid,
    List,
}

#[component]
pub fn OpViewToggle(
    mode: ReadSignal<OpViewMode>,
    set_mode: WriteSignal<OpViewMode>,
) -> impl IntoView {
    view! {
        <div class="inline-flex rounded-lg border border-zinc-800 bg-zinc-900/60 p-0.5">
            <button
                type="button"
                class=move || {
                    if mode.get() == OpViewMode::Grid {
                        "rounded-md bg-zinc-800 px-2.5 py-1 text-xs font-medium text-zinc-100"
                    } else {
                        "rounded-md px-2.5 py-1 text-xs font-medium text-zinc-500 hover:text-zinc-300"
                    }
                }
                aria-label="Grid view"
                on:click=move |_| set_mode.set(OpViewMode::Grid)
            >
                "▦"
            </button>
            <button
                type="button"
                class=move || {
                    if mode.get() == OpViewMode::List {
                        "rounded-md bg-zinc-800 px-2.5 py-1 text-xs font-medium text-zinc-100"
                    } else {
                        "rounded-md px-2.5 py-1 text-xs font-medium text-zinc-500 hover:text-zinc-300"
                    }
                }
                aria-label="List view"
                on:click=move |_| set_mode.set(OpViewMode::List)
            >
                "≡"
            </button>
        </div>
    }
}

#[component]
pub fn OpFilterTabs(
    tabs: Vec<(&'static str, &'static str)>,
    active: ReadSignal<String>,
    set_active: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <div class="flex flex-wrap gap-1">
            {tabs.into_iter().map(|(id, label)| {
                let id_static = id;
                view! {
                    <button
                        type="button"
                        class=move || {
                            if active.get() == id_static {
                                "rounded-lg bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-100"
                            } else {
                                "rounded-lg px-3 py-1.5 text-xs font-medium text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900"
                            }
                        }
                        on:click=move |_| set_active.set(id_static.to_string())
                    >
                        {label}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}
