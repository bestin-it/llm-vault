//! Desktop UI glue: pushes core state into the Slint `Store` global and implements its callbacks.
//! Everything here runs in-process; the UI never talks to the gateway over the network.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use zeroize::Zeroizing;

use llmvault::audit::{Filter, RequestRecord};
use llmvault::config::{AuthStyle, ClientConfig, ConsentMode, FxRate, ModelAlias, PriceVersion, ProviderConfig, ProviderKind, new_id, now_rfc3339};
use llmvault::core::{Core, UiEvent};
use llmvault::policy::{ConsentDecision, new_client_token};
use llmvault::providers::{self, CATALOG, Upstream};
use llmvault::vault::{EntryInput, generate_password, password_entropy_bits};

use crate::{
    AppWindow, BarItem, CheckItem, ClientItem, ConsentItem, DayItem, EntryItem, EventItem, FxItem, GroupItem, ModelItem, PresetItem, PriceItem,
    ProviderItem, RequestItem, RuleItem, Store,
};

/// UI-thread-only state (index <-> id maps for combo boxes etc.).
#[derive(Default)]
struct UiState {
    group_ids: Vec<String>,
    provider_ids: Vec<String>,
    provider_status: std::collections::HashMap<String, (String, bool)>,
    filter_providers: Vec<String>,
    filter_models: Vec<String>,
    filter_clients: Vec<String>,
}

type Shared = Rc<RefCell<UiState>>;

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn ss(s: impl AsRef<str>) -> SharedString {
    SharedString::from(s.as_ref())
}

fn toast(ui: &AppWindow, msg: impl AsRef<str>, error: bool) {
    let st = ui.global::<Store>();
    st.set_toast(ss(msg));
    st.set_toast_error(error);
}

fn fmt_num(n: u64) -> String {
    match n {
        n if n >= 1_000_000_000 => format!("{:.1} B", n as f64 / 1e9),
        n if n >= 1_000_000 => format!("{:.1} M", n as f64 / 1e6),
        n if n >= 10_000 => format!("{:.1} k", n as f64 / 1e3),
        n => {
            let s = n.to_string();
            if s.len() > 3 { format!("{},{}", &s[..s.len() - 3], &s[s.len() - 3..]) } else { s }
        }
    }
}

fn fmt_money(v: f64, cur: &str) -> String {
    if v == 0.0 {
        format!("0.00 {cur}")
    } else if v.abs() < 0.01 {
        format!("{v:.4} {cur}")
    } else {
        format!("{v:.2} {cur}")
    }
}

fn fmt_ts(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts).map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_else(|_| ts.to_string())
}

fn parse_f64(s: &str) -> Result<f64, String> {
    let t = s.trim().replace(',', ".");
    if t.is_empty() {
        return Ok(0.0);
    }
    t.parse::<f64>().ok().filter(|v| v.is_finite() && *v >= 0.0).ok_or_else(|| format!("'{s}' is not a valid non-negative number"))
}

fn request_item(r: &RequestRecord) -> RequestItem {
    let ok = r.decision == "allowed" && (200..300).contains(&r.status);
    RequestItem {
        ts: ss(fmt_ts(&r.ts)),
        client: ss(if r.client_name.is_empty() { "(unknown client)" } else { &r.client_name }),
        agent: ss(&r.agent),
        project: ss(&r.project),
        model: ss(&r.model_alias),
        provider: ss(if r.provider_name.is_empty() { "-".to_string() } else { format!("{} · {}", r.provider_name, r.upstream_model) }),
        decision: ss(&r.decision),
        consent: ss(if r.consent.is_empty() { "-" } else { &r.consent }),
        status: r.status as i32,
        latency: ss(if r.latency_ms > 0 { format!("{} ms", r.latency_ms) } else { String::new() }),
        tokens: ss(if r.usage.total() > 0 { format!("{} / {}", fmt_num(r.usage.input), fmt_num(r.usage.output)) } else { "-".into() }),
        cost: ss(if r.currency.is_empty() { "-".to_string() } else { fmt_money(r.cost, &r.currency) }),
        source: ss(if r.usage.total() > 0 { r.usage.source.as_str() } else { "" }),
        error: ss(&r.error),
        ok,
        denied: r.decision == "denied",
        endpoint: ss(&r.endpoint),
    }
}

// ======================================================================= refreshers

fn refresh_header(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    st.set_gateway_url(ss(core.gateway_url().unwrap_or_default()));
    st.set_gateway_error(ss(core.gateway_error.lock().unwrap().clone().unwrap_or_default()));
    if let Some((name, path)) = core.with_vault(|v| (v.name(), v.path().display().to_string())) {
        st.set_vault_name(ss(name));
        st.set_vault_path(ss(path));
    }
}

fn refresh_dashboard(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    let days = [7, 30, 90, 365][st.get_period_index().clamp(0, 3) as usize];
    let cur = core.with_vault(|v| v.config.display_currency.clone()).unwrap_or_else(|| "USD".into());
    let fx = core.fx_to_display();
    let s = core.audit().summary(&Filter { days, ..Default::default() }, &fx);
    st.set_currency(ss(&cur));
    st.set_kpi_calls(ss(fmt_num(s.calls)));
    st.set_kpi_calls_sub(ss(format!("{} ok · {} errors · {} denied", s.ok, s.errors, s.denied)));
    let tokens = s.input + s.output;
    st.set_kpi_tokens(ss(fmt_num(tokens)));
    st.set_kpi_tokens_sub(ss(if tokens > 0 {
        format!("{:.0}% input · {} cached", s.input as f64 * 100.0 / tokens as f64, fmt_num(s.cache_read))
    } else {
        "input / output / cached".into()
    }));
    st.set_kpi_cost(ss(format!("{:.2}", s.cost)));
    st.set_kpi_cost_sub(ss(if s.estimated_cost > 0.0 { format!("calculated · {:.2} estimated", s.estimated_cost) } else { "calculated from price lists".into() }));
    st.set_kpi_latency(ss(if s.avg_latency_ms > 0.0 { format!("{:.0} ms", s.avg_latency_ms) } else { "-".into() }));
    st.set_kpi_latency_sub(ss(if s.p95_latency_ms > 0 { format!("p95 {} ms", s.p95_latency_ms) } else { "average / p95".into() }));

    let bars = |b: &[llmvault::audit::Bucket], n: usize| -> Vec<BarItem> {
        let max_cost = b.iter().map(|x| x.cost).fold(0.0, f64::max);
        let max_calls = b.iter().map(|x| x.calls).max().unwrap_or(0) as f64;
        b.iter()
            .take(n)
            .map(|x| BarItem {
                label: ss(&x.label),
                value: if max_cost > 0.0 { (x.cost / max_cost) as f32 } else if max_calls > 0.0 { (x.calls as f64 / max_calls) as f32 } else { 0.0 },
                amount: ss(fmt_money(x.cost, &cur)),
                sub: ss(format!("{} calls · {} tokens", fmt_num(x.calls), fmt_num(x.tokens))),
            })
            .collect()
    };
    st.set_cost_by_provider(model(bars(&s.by_provider, 6)));
    st.set_top_models(model(bars(&s.by_model, 5)));
    let mut agents = s.by_client.clone();
    if agents.len() < 2 && s.by_agent.len() > agents.len() {
        agents = s.by_agent.clone();
    }
    st.set_top_agents(model(bars(&agents, 5)));
    let max_day = s.daily.iter().map(|d| d.cost).fold(0.0, f64::max);
    let max_day_calls = s.daily.iter().map(|d| d.calls).max().unwrap_or(0) as f64;
    st.set_daily(model(
        s.daily
            .iter()
            .map(|d| DayItem {
                day: ss(&d.day),
                value: if max_day > 0.0 { (d.cost / max_day) as f32 } else if max_day_calls > 0.0 { (d.calls as f64 / max_day_calls) as f32 } else { 0.0 },
                label: ss(format!("{} · {} calls", fmt_money(d.cost, &cur), d.calls)),
            })
            .collect(),
    ));
    let recent = core.audit().requests(&Filter { days, ..Default::default() }, 8);
    st.set_recent(model(recent.iter().map(request_item).collect()));
    if let Some((p, m, c, r, e)) = core.with_vault(|v| {
        (
            v.config.providers.len(),
            v.config.models.len(),
            v.config.clients.iter().filter(|c| !c.revoked).count(),
            v.config.consent_rules.len(),
            v.entries(None, "").len(),
        )
    }) {
        st.set_stat_providers(p as i32);
        st.set_stat_models(m as i32);
        st.set_stat_clients(c as i32);
        st.set_stat_rules((r + core.session_grants().len()) as i32);
        st.set_stat_entries(e as i32);
    }
}

fn refresh_passwords(ui: &AppWindow, core: &Core, state: &Shared) {
    let st = ui.global::<Store>();
    let groups = core.with_vault(|v| v.groups()).unwrap_or_default();
    // skip the root group in the list (it is the database itself)
    let visible: Vec<_> = groups.iter().filter(|g| g.depth > 0).collect();
    st.set_groups(model(
        visible
            .iter()
            .map(|g| GroupItem { id: ss(&g.id), name: ss(&g.name), depth: g.depth - 1, count: g.entry_count, provider: g.is_provider_group })
            .collect(),
    ));
    let mut s = state.borrow_mut();
    s.group_ids = visible.iter().map(|g| g.id.clone()).collect();
    st.set_group_names(model(visible.iter().map(|g| ss(format!("{}{}", "   ".repeat((g.depth - 1).max(0) as usize), g.name))).collect()));
    drop(s);
    let group = st.get_selected_group().to_string();
    let entries = core.with_vault(|v| v.entries(if group.is_empty() { None } else { Some(group.as_str()) }, &st.get_search())).unwrap_or_default();
    st.set_entries(model(
        entries
            .iter()
            .map(|e| EntryItem {
                id: ss(&e.id),
                group_id: ss(&e.group_id),
                group_name: ss(&e.group_name),
                title: ss(&e.title),
                username: ss(&e.username),
                url: ss(&e.url),
                notes: ss(&e.notes),
                tags: ss(&e.tags),
                has_password: e.has_password,
                provider: e.is_provider_key,
                modified: ss(&e.modified),
                expires: ss(&e.expires),
            })
            .collect(),
    ));
}

fn refresh_providers(ui: &AppWindow, core: &Core, state: &Shared) {
    let st = ui.global::<Store>();
    let filter = st.get_catalog_filter().to_string();
    st.set_presets(model(
        CATALOG
            .iter()
            .filter(|p| filter == "All" || p.category == filter)
            .map(|p| PresetItem {
                id: ss(p.id),
                name: ss(p.name),
                category: ss(p.category),
                description: ss(p.description),
                needs_key: p.needs_key,
                base_url: ss(p.base_url),
                key_url: ss(p.key_url),
                examples: ss(p.example_models.join(", ")),
                kind: ss(p.kind.as_str()),
            })
            .collect(),
    ));
    let statuses = state.borrow().provider_status.clone();
    let items = core
        .with_vault(|v| {
            v.config
                .providers
                .iter()
                .map(|p| {
                    let (status, ok) = statuses.get(&p.id).cloned().unwrap_or_default();
                    ProviderItem {
                        id: ss(&p.id),
                        name: ss(&p.name),
                        preset: ss(&p.preset),
                        kind: ss(p.kind.as_str()),
                        base_url: ss(&p.base_url),
                        has_key: p.secret_entry.as_deref().map(|id| v.entry(id).map(|e| e.has_password).unwrap_or(false)).unwrap_or(false),
                        enabled: p.enabled,
                        allow_http: p.allow_http,
                        api_version: ss(p.api_version.clone().unwrap_or_default()),
                        models: v.config.models.iter().filter(|m| m.provider_id == p.id).count() as i32,
                        status: ss(status),
                        status_ok: ok,
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    st.set_providers(model(items));
}

fn refresh_models(ui: &AppWindow, core: &Core, state: &Shared) {
    let st = ui.global::<Store>();
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let (items, provs) = core
        .with_vault(|v| {
            let items: Vec<ModelItem> = v
                .config
                .models
                .iter()
                .map(|m| {
                    let price = llmvault::pricing::price_for(&v.config.prices, &m.alias, &today)
                        .map(|p| format!("{} · {} · {} {}{}", p.input, p.output, p.cache_read, p.currency, if p.estimated { " (est.)" } else { "" }))
                        .unwrap_or_else(|| "no price".into());
                    ModelItem {
                        alias: ss(&m.alias),
                        provider_id: ss(&m.provider_id),
                        provider_name: ss(v.config.provider(&m.provider_id).map(|p| p.name.as_str()).unwrap_or("(missing provider)")),
                        upstream: ss(&m.upstream_model),
                        description: ss(&m.description),
                        enabled: m.enabled,
                        price: ss(price),
                    }
                })
                .collect();
            let provs: Vec<(String, String)> = v.config.providers.iter().map(|p| (p.id.clone(), p.name.clone())).collect();
            (items, provs)
        })
        .unwrap_or_default();
    st.set_models(model(items));
    st.set_provider_names(model(provs.iter().map(|(_, n)| ss(n)).collect()));
    state.borrow_mut().provider_ids = provs.into_iter().map(|(id, _)| id).collect();
    refresh_prices(ui, core);
}

fn refresh_prices(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    let alias = st.get_m_orig_alias().to_string();
    let prices = core
        .with_vault(|v| {
            let mut p: Vec<PriceVersion> = v.config.prices.iter().filter(|p| p.alias == alias).cloned().collect();
            p.sort_by(|a, b| b.effective_from.cmp(&a.effective_from));
            p
        })
        .unwrap_or_default();
    st.set_prices(model(
        prices
            .iter()
            .map(|p| PriceItem {
                id: ss(&p.id),
                alias: ss(&p.alias),
                currency: ss(&p.currency),
                input: ss(p.input.to_string()),
                output: ss(p.output.to_string()),
                cache_read: ss(p.cache_read.to_string()),
                cache_write: ss(p.cache_write.to_string()),
                reasoning: ss(p.reasoning.to_string()),
                effective: ss(&p.effective_from),
                source: ss(&p.source),
                estimated: p.estimated,
            })
            .collect(),
    ));
}

fn refresh_clients(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let clients = core.with_vault(|v| (v.config.clients.clone(), v.config.fx_rates.clone())).unwrap_or_default();
    let now = chrono::Utc::now();
    st.set_clients(model(
        clients
            .0
            .iter()
            .map(|c| {
                let spent: f64 = core
                    .audit()
                    .client_spend(&c.id, &today)
                    .into_iter()
                    .map(|(cur, amt)| amt / clients.1.iter().find(|r| r.currency == cur).map(|r| r.per_usd).filter(|r| *r > 0.0).unwrap_or(1.0))
                    .sum();
                let expired = c.expires_at.as_deref().and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok()).map(|e| e < now).unwrap_or(false);
                let mut limits = Vec::new();
                if c.daily_budget > 0.0 {
                    limits.push(format!("{:.2} USD/day", c.daily_budget));
                }
                if c.monthly_budget > 0.0 {
                    limits.push(format!("{:.2} USD/month", c.monthly_budget));
                }
                if c.rpm_limit > 0 {
                    limits.push(format!("{} req/min", c.rpm_limit));
                }
                ClientItem {
                    id: ss(&c.id),
                    name: ss(&c.name),
                    project: ss(&c.project),
                    prefix: ss(&c.token_prefix),
                    models: ss(if c.allowed_models.is_empty() { "all".to_string() } else { c.allowed_models.join(", ") }),
                    mode: ss(match c.consent_mode {
                        ConsentMode::Ask => "ask every time",
                        ConsentMode::Session => "ask once per session",
                        ConsentMode::Auto => "pre-approved",
                    }),
                    expires: ss(c.expires_at.as_deref().map(fmt_ts).unwrap_or_else(|| "never".into())),
                    limits: ss(if limits.is_empty() { "no limits".to_string() } else { limits.join(" · ") }),
                    revoked: c.revoked,
                    expired,
                    last_used: ss(core.audit().last_used(&c.id).map(|t| fmt_ts(&t)).unwrap_or_else(|| "never".into())),
                    spent: ss(format!("{spent:.4} USD")),
                }
            })
            .collect(),
    ));
}

fn refresh_consents(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    st.set_pending(model(
        core.pending_consents()
            .iter()
            .map(|c| ConsentItem {
                id: ss(&c.id),
                client: ss(&c.client_name),
                agent: ss(&c.agent),
                project: ss(&c.project),
                model: ss(&c.model_alias),
                provider: ss(&c.provider_name),
                upstream: ss(&c.upstream_model),
                mode: ss(c.mode.as_str()),
                requested: ss(fmt_ts(&c.requested_at)),
            })
            .collect(),
    ));
    let rules = core
        .with_vault(|v| {
            let name = |id: &str| v.config.client(id).map(|c| c.name.clone()).unwrap_or_else(|| "(deleted client)".into());
            let mut out: Vec<RuleItem> = Vec::new();
            for c in v.config.clients.iter().filter(|c| c.consent_mode == ConsentMode::Auto && !c.revoked) {
                out.push(RuleItem {
                    id: ss(&c.id),
                    kind: ss("pre-approved"),
                    client_id: ss(&c.id),
                    client: ss(&c.name),
                    model: ss(if c.allowed_models.is_empty() { "all models".to_string() } else { c.allowed_models.join(", ") }),
                    created: ss(format!("client created {}", fmt_ts(&c.created_at))),
                });
            }
            for r in &v.config.consent_rules {
                out.push(RuleItem {
                    id: ss(&r.id),
                    kind: ss("always"),
                    client_id: ss(&r.client_id),
                    client: ss(name(&r.client_id)),
                    model: ss(&r.model_alias),
                    created: ss(format!("granted {}", fmt_ts(&r.created_at))),
                });
            }
            for (cid, alias) in core.session_grants() {
                out.push(RuleItem {
                    id: ss(&cid),
                    kind: ss("session"),
                    client_id: ss(&cid),
                    client: ss(name(&cid)),
                    model: ss(&alias),
                    created: ss("until the vault is locked"),
                });
            }
            out
        })
        .unwrap_or_default();
    st.set_rules(model(rules));
}

fn activity_filter(ui: &AppWindow, state: &Shared) -> Filter {
    let st = ui.global::<Store>();
    let s = state.borrow();
    let pick = |list: &Vec<String>, idx: i32| if idx <= 0 { String::new() } else { list.get(idx as usize - 1).cloned().unwrap_or_default() };
    Filter {
        days: [7, 30, 90, 365, 0][st.get_f_period().clamp(0, 4) as usize],
        provider: pick(&s.filter_providers, st.get_f_provider()),
        model: pick(&s.filter_models, st.get_f_model()),
        client: pick(&s.filter_clients, st.get_f_client()),
        status: ["", "ok", "error", "denied"][st.get_f_status().clamp(0, 3) as usize].into(),
        search: st.get_f_search().trim().to_string(),
    }
}

fn refresh_activity(ui: &AppWindow, core: &Core, state: &Shared) {
    let st = ui.global::<Store>();
    {
        let mut s = state.borrow_mut();
        s.filter_providers = core.audit().distinct("provider");
        s.filter_models = core.audit().distinct("model");
        s.filter_clients = core.audit().distinct("client");
        let with_all = |all: &str, v: &Vec<String>| model(std::iter::once(ss(all)).chain(v.iter().map(ss)).collect());
        st.set_f_providers(with_all("All providers", &s.filter_providers));
        st.set_f_models(with_all("All models", &s.filter_models));
        st.set_f_clients(with_all("All clients", &s.filter_clients));
    }
    let f = activity_filter(ui, state);
    st.set_requests(model(core.audit().requests(&f, 500).iter().map(request_item).collect()));
    st.set_events(model(
        core.audit().events(300).into_iter().map(|(ts, kind, message)| EventItem { ts: ss(fmt_ts(&ts)), kind: ss(kind), message: ss(message) }).collect(),
    ));
}

fn refresh_settings(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    if let Some(cfg) = core.with_vault(|v| v.config.clone()) {
        st.set_s_host(ss(&cfg.gateway.host));
        st.set_s_port(ss(cfg.gateway.port.to_string()));
        st.set_s_consent_timeout(ss(cfg.gateway.consent_timeout_s.to_string()));
        st.set_s_autolock(ss(cfg.security.auto_lock_minutes.to_string()));
        st.set_s_clip(ss(cfg.security.clipboard_clear_s.to_string()));
        st.set_s_arm(ss(cfg.security.consent_arm_ms.to_string()));
        st.set_consent_arm_ms(cfg.security.consent_arm_ms as i32);
        st.set_s_currency_index(["USD", "EUR", "PLN"].iter().position(|c| *c == cfg.display_currency).unwrap_or(0) as i32);
        st.set_fx(model(
            cfg.fx_rates
                .iter()
                .filter(|r| r.currency != "USD")
                .map(|r| FxItem { currency: ss(&r.currency), rate: ss(format!("{}", r.per_usd)), date: ss(&r.date), source: ss(&r.source) })
                .collect(),
        ));
        if st.get_s_fx_date().is_empty() {
            st.set_s_fx_date(ss(chrono::Local::now().format("%Y-%m-%d").to_string()));
        }
    }
    st.set_data_dir(ss(core.paths().data_dir.display().to_string()));
}

fn refresh_page(ui: &AppWindow, core: &Core, state: &Shared) {
    refresh_header(ui, core);
    refresh_consents(ui, core);
    match ui.global::<Store>().get_page() {
        0 => refresh_dashboard(ui, core),
        1 => refresh_passwords(ui, core, state),
        2 => refresh_providers(ui, core, state),
        3 => refresh_models(ui, core, state),
        4 => refresh_clients(ui, core),
        5 => {}
        6 => refresh_activity(ui, core, state),
        _ => refresh_settings(ui, core),
    }
}

fn after_unlock(ui: &AppWindow, core: &Core, state: &Shared) {
    let st = ui.global::<Store>();
    st.set_unlocked(true);
    st.set_unlock_error(ss(""));
    st.set_page(0);
    st.set_editor_open(false);
    refresh_settings(ui, core);
    refresh_page(ui, core, state);
    if let Some(e) = core.gateway_error.lock().unwrap().clone() {
        toast(ui, format!("Gateway not started: {e}"), true);
    }
}

fn show_locked(ui: &AppWindow) {
    let st = ui.global::<Store>();
    st.set_unlocked(false);
    st.set_welcome_mode(ss("unlock"));
    st.set_editor_open(false);
    st.set_e_password(ss(""));
    st.set_pd_key(ss(""));
    st.set_new_token(ss(""));
    st.set_token_dialog(false);
    st.set_provider_dialog(false);
    st.set_discover_dialog(false);
    st.set_confirm_open(false);
    st.set_pending(model(vec![]));
    st.set_entries(model(vec![]));
}

// ======================================================================= profiles

fn init_welcome(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    let store = core.profiles.lock().unwrap();
    st.set_profile_names(model(store.profiles.iter().map(|p| ss(&p.username)).collect()));
    st.set_login_username(ss(store.last_username.clone().or_else(|| store.profiles.first().map(|p| p.username.clone())).unwrap_or_default()));
    st.set_signed_in(false);
    st.set_welcome_mode(ss(if store.profiles.is_empty() { "register" } else { "login" }));
}

/// After sign-in: point the welcome screen at this profile's vault (unlock or create).
fn prepare_vault_step(ui: &AppWindow, core: &Core) {
    let st = ui.global::<Store>();
    let Some(user) = core.current_user() else { return };
    let initials: String = {
        let base = if user.display_name.trim().is_empty() { &user.username } else { &user.display_name };
        base.split_whitespace().filter_map(|w| w.chars().next()).take(2).collect::<String>().to_uppercase()
    };
    st.set_user_label(ss(if user.display_name.trim().is_empty() { user.username.clone() } else { user.display_name.clone() }));
    st.set_user_initials(ss(initials));
    st.set_signed_in(true);
    st.set_unlock_error(ss(""));
    let paths = core.paths();
    st.set_new_vault_path(ss(paths.default_vault().display().to_string()));
    let s = core.settings.lock().unwrap();
    let existing = s.last_vault.clone().filter(|p| p.exists()).or_else(|| Some(paths.default_vault()).filter(|p| p.exists()));
    match existing {
        Some(p) => {
            st.set_vault_path(ss(p.display().to_string()));
            st.set_welcome_mode(ss("unlock"));
        }
        None => {
            st.set_vault_path(ss(""));
            st.set_welcome_mode(ss("create"));
        }
    }
    st.set_keyfile_path(ss(s.last_keyfile.as_ref().map(|k| k.display().to_string()).unwrap_or_default()));
}

// ======================================================================= clipboard

fn copy_secret(ui: &AppWindow, core: &Core, value: Zeroizing<String>, what: &str) {
    let secs = core.with_vault(|v| v.config.security.clipboard_clear_s).unwrap_or(15).max(5);
    let mut cb = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => return toast(ui, format!("Clipboard unavailable: {e}"), true),
    };
    #[cfg(target_os = "windows")]
    let r = {
        use arboard::SetExtWindows;
        cb.set().exclude_from_history().exclude_from_cloud().exclude_from_monitoring().text(value.as_str())
    };
    #[cfg(not(target_os = "windows"))]
    let r = cb.set_text(value.as_str());
    if let Err(e) = r {
        return toast(ui, format!("Copy failed: {e}"), true);
    }
    toast(ui, format!("{what} copied - clipboard will be cleared in {secs} s"), false);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs as u64));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if cb.get_text().map(|t| t == *value).unwrap_or(false) {
                let _ = cb.clear();
            }
        }
    });
}

fn copy_plain(ui: &AppWindow, text: &str) {
    if text.is_empty() {
        return;
    }
    match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
        Ok(_) => toast(ui, "Copied to clipboard", false),
        Err(e) => toast(ui, format!("Copy failed: {e}"), true),
    }
}

// ======================================================================= snippets

fn snippet(index: i32, url: &str, token: &str, models: &[String]) -> String {
    let base = if url.is_empty() { "http://127.0.0.1:8765/v1" } else { url };
    let root = base.trim_end_matches("/v1");
    let model = models.first().map(String::as_str).unwrap_or("your-model-alias");
    match index {
        0 => format!(
            "# pip install openai\nimport os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url=\"{base}\",\n    api_key=os.environ[\"VAULT_CLIENT_TOKEN\"],  # {token}\n    default_headers={{\"X-LLMVault-Agent\": \"python-script\"}},\n)\n\nreply = client.chat.completions.create(\n    model=\"{model}\",\n    messages=[{{\"role\": \"user\", \"content\": \"Review this code\"}}],\n)\nprint(reply.choices[0].message.content)\n"
        ),
        1 => format!(
            "# PowerShell\n$env:OPENAI_BASE_URL = \"{base}\"\n$env:OPENAI_API_KEY  = \"{token}\"\n$env:VAULT_CLIENT_TOKEN = \"{token}\"\n\n# bash / zsh\nexport OPENAI_BASE_URL=\"{base}\"\nexport OPENAI_API_KEY=\"{token}\"\nexport VAULT_CLIENT_TOKEN=\"{token}\"\n"
        ),
        2 => format!(
            "# Claude Code -> LLM Vault (/v1/messages, Anthropic or Ollama provider)\n# PowerShell\n$env:ANTHROPIC_BASE_URL = \"{root}\"\n$env:ANTHROPIC_AUTH_TOKEN = \"{token}\"\n$env:ANTHROPIC_MODEL = \"{model}\"\nclaude\n\n# bash\nANTHROPIC_BASE_URL={root} ANTHROPIC_AUTH_TOKEN={token} ANTHROPIC_MODEL={model} claude\n"
        ),
        3 => {
            // one Custom Endpoint model per alias the token may use, so all of them show up in the Copilot picker
            let entries: Vec<String> = models
                .iter()
                .map(|m| {
                    format!(
                        "      {{
        \"id\": \"{m}\",
        \"name\": \"{m} (LLM Vault)\",
        \"url\": \"{base}/chat/completions\",
        \"toolCalling\": true,
        \"vision\": false,
        \"maxInputTokens\": 128000,
        \"maxOutputTokens\": 16000,
        \"requestHeaders\": {{ \"X-LLMVault-Agent\": \"vscode-copilot\" }}
      }}"
                    )
                })
                .collect();
            let entries = entries.join(",\n");
            format!(
                "VS Code > GitHub Copilot Chat > Manage Language Models > Add Models > Custom Endpoint
(API type: Chat Completions). Or paste into chatLanguageModels.json:

[
  {{
    \"name\": \"LLM Vault\",
    \"vendor\": \"customendpoint\",
    \"apiKey\": \"${{input:llmVaultToken}}\",
    \"apiType\": \"chat-completions\",
    \"models\": [
{entries}
    ]
  }}
]

When VS Code asks for llmVaultToken, paste: {token}
Agents in .github/agents/*.agent.md can then use model: {model} (LLM Vault).
Copilot Business/Enterprise: the 'Bring Your Own Language Model Key in VS Code' policy must be enabled.
"
            )
        }
        _ => format!(
            "curl {base}/chat/completions \\\n  -H \"Authorization: Bearer {token}\" \\\n  -H \"Content-Type: application/json\" \\\n  -H \"X-LLMVault-Agent: curl\" \\\n  -d '{{\"model\": \"{model}\", \"messages\": [{{\"role\": \"user\", \"content\": \"Hello\"}}]}}'\n"
        ),
    }
}

/// Aliases the client may use (all configured aliases when the token is unrestricted), in the token's order.
fn models_for(core: &Core, client_id: &str) -> Vec<String> {
    core.with_vault(|v| match v.config.client(client_id) {
        Some(c) if !c.allowed_models.is_empty() => c.allowed_models.clone(),
        _ => v.config.models.iter().map(|m| m.alias.clone()).collect(),
    })
    .unwrap_or_default()
}

fn show_token(ui: &AppWindow, core: &Core, client_name: &str, client_id: &str, token: String) {
    let st = ui.global::<Store>();
    st.set_new_token_client(ss(client_name));
    st.set_snippet_index(0);
    st.set_snippet(ss(snippet(0, &core.gateway_url().unwrap_or_default(), &token, &models_for(core, client_id))));
    st.set_new_token(ss(token));
    st.set_token_dialog(true);
}

// ======================================================================= provider helpers

fn sanitize_alias(name: &str) -> String {
    let s: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '-' })
        .collect();
    s.trim_matches('-').to_string()
}

fn valid_alias(a: &str) -> bool {
    !a.is_empty() && a.len() <= 80 && a.chars().all(|c| c.is_ascii_alphanumeric() || "._-:/".contains(c))
}

fn upstream_for(core: &Core, id: &str) -> Option<(Upstream, String)> {
    core.with_vault(|v| {
        let p = v.config.provider(id)?;
        let secret = p.secret_entry.as_deref().and_then(|e| v.entry_password(e)).filter(|s| !s.is_empty());
        Some((Upstream::from_config(p, secret), p.name.clone()))
    })
    .flatten()
}

fn run_discovery(ui: &AppWindow, core: &Arc<Core>, provider_id: String) {
    let st = ui.global::<Store>();
    let Some((up, name)) = upstream_for(core, &provider_id) else { return };
    st.set_discover_provider(ss(&provider_id));
    st.set_discovered(model(vec![]));
    st.set_discover_status(ss(format!("Asking {name} for its model list...")));
    st.set_discover_dialog(true);
    let weak = ui.as_weak();
    let c2 = core.clone();
    core.rt.spawn(async move {
        let r = providers::discover_models(&c2.http, &up).await;
        let existing: Vec<String> = c2.with_vault(|v| v.config.models.iter().filter(|m| m.provider_id == provider_id).map(|m| m.upstream_model.clone()).collect()).unwrap_or_default();
        let r = r.map(|list| list.into_iter().filter(|n| !existing.contains(n)).collect::<Vec<_>>());
        let msg = r.as_ref().err().map(|e| c2.redact(&e.to_string()));
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let st = ui.global::<Store>();
            match r {
                Ok(list) => {
                    st.set_discover_status(ss(if list.is_empty() {
                        "The provider returned no models. You can still add an alias manually on the Models page.".to_string()
                    } else {
                        format!("{} new model(s) available (models that already have an alias are hidden).", list.len())
                    }));
                    st.set_discovered(model(list.into_iter().map(|n| CheckItem { checked: false, name: ss(n) }).collect()));
                }
                Err(_) => st.set_discover_status(ss(format!("Could not list models: {}", msg.unwrap_or_default()))),
            }
        });
    });
}

fn confirm(ui: &AppWindow, title: &str, text: &str, action: &str, arg: &str, arg2: &str) {
    let st = ui.global::<Store>();
    st.set_confirm_expected(ss(if action == "delete-profile" { arg } else { "" }));
    st.set_confirm_input(ss(""));
    st.set_confirm_title(ss(title));
    st.set_confirm_text(ss(text));
    st.set_confirm_action(ss(action));
    st.set_confirm_arg(ss(arg));
    st.set_confirm_arg2(ss(arg2));
    st.set_confirm_open(true);
}

// ======================================================================= wiring

/// Startup options (used by `--demo`, `--page`, `--snapshot`, `--consent`).
#[derive(Default)]
pub struct LaunchOptions {
    pub page: Option<i32>,
    pub snapshot: Option<PathBuf>,
    pub consent_token: Option<String>,
    /// Show the one-time token dialog with the given quick-start snippet (demo / screenshots).
    pub token_snippet: Option<i32>,
    /// `--tour <script.json> --record <out.mp4>` (demo only): scripted UI run recorded to video.
    pub tour: Option<(PathBuf, PathBuf)>,
}

pub fn run(core: Arc<Core>, opts: LaunchOptions) -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let state: Shared = Rc::new(RefCell::new(UiState::default()));
    let st = ui.global::<Store>();
    st.set_version(ss(env!("CARGO_PKG_VERSION")));

    init_welcome(&ui, &core);
    if core.current_user().is_some() {
        prepare_vault_step(&ui, &core);
    }

    // ---- core -> UI events
    {
        let weak = ui.as_weak();
        let c = core.clone();
        core.set_notifier(move |ev| {
            let weak = weak.clone();
            let c = c.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else { return };
                match ev {
                    UiEvent::ConsentRequested(_) => {
                        refresh_consents(&ui, &c);
                        let _ = ui.show();
                        ui.window().set_minimized(false);
                    }
                    UiEvent::ConsentClosed(_) => refresh_consents(&ui, &c),
                    UiEvent::RequestFinished => {
                        let st = ui.global::<Store>();
                        if st.get_unlocked() && st.get_page() == 0 {
                            refresh_dashboard(&ui, &c);
                        }
                    }
                    UiEvent::Locked(reason) => {
                        show_locked(&ui);
                        toast(&ui, format!("Vault locked ({reason})"), false);
                    }
                }
            });
        });
    }

    // ---- housekeeping timer (auto-lock, gateway status)
    let timer = slint::Timer::default();
    {
        let weak = ui.as_weak();
        let c = core.clone();
        timer.start(slint::TimerMode::Repeated, Duration::from_secs(2), move || {
            c.tick();
            if let Some(ui) = weak.upgrade() {
                let st = ui.global::<Store>();
                if st.get_unlocked() && !c.is_unlocked() {
                    show_locked(&ui);
                }
                if st.get_unlocked() {
                    refresh_header(&ui, &c);
                }
            }
        });
    }

    macro_rules! cb {
        ($name:ident, |$ui:ident, $core:ident, $state:ident $(, $arg:ident : $t:ty)*| $body:block) => {{
            let weak = ui.as_weak();
            let core_ = core.clone();
            let state_ = state.clone();
            st.$name(move |$($arg: $t),*| {
                let Some($ui) = weak.upgrade() else { return Default::default() };
                let _ = &$ui;
                let $core = &core_;
                let $state = &state_;
                $core.touch();
                #[allow(unused_variables)]
                let _ = &$state;
                $body
            });
        }};
    }

    // ------------------------------------------------------------ profiles
    cb!(on_login, |ui, core, state, user: SharedString, pw: SharedString| {
        let st = ui.global::<Store>();
        let pw = Zeroizing::new(pw.to_string());
        st.set_busy(true);
        let r = core.login(&user, &pw);
        st.set_busy(false);
        match r {
            Ok(_) => prepare_vault_step(&ui, core),
            Err(e) => st.set_unlock_error(ss(e.to_string())),
        }
    });
    cb!(on_register, |ui, core, state, user: SharedString, display: SharedString, pw: SharedString, pw2: SharedString| {
        let st = ui.global::<Store>();
        if pw != pw2 {
            return st.set_unlock_error(ss("The passwords do not match."));
        }
        let pw = Zeroizing::new(pw.to_string());
        st.set_busy(true);
        let r = core.register(&user, &display, &pw);
        st.set_busy(false);
        match r {
            Ok(_) => {
                prepare_vault_step(&ui, core);
                toast(&ui, "Profile created. Now create your encrypted vault (or open an existing KeePass file).", false);
            }
            Err(e) => st.set_unlock_error(ss(e.to_string())),
        }
    });
    cb!(on_logout, |ui, core, state| {
        core.logout();
        show_locked(&ui);
        init_welcome(&ui, core);
    });
    cb!(on_delete_profile, |ui, core, state, user: SharedString| {
        if core.profiles.lock().unwrap().find(&user).is_none() {
            return ui.global::<Store>().set_unlock_error(ss("Type the user name of the profile you want to delete."));
        }
        confirm(
            &ui,
            "Delete profile?",
            &format!("There is no password reset in LLM Vault. Deleting '{user}' removes the profile and its data folder (vault files stored inside it, audit log, settings). Vault files saved elsewhere are kept. This cannot be undone."),
            "delete-profile",
            &user,
            "",
        );
    });
    cb!(on_change_login_password, |ui, core, state| {
        let st = ui.global::<Store>();
        let Some(u) = core.current_user() else { return };
        let (cur, new, new2) = (Zeroizing::new(st.get_login_cur().to_string()), Zeroizing::new(st.get_login_new().to_string()), st.get_login_new2());
        st.set_login_cur(ss(""));
        st.set_login_new(ss(""));
        st.set_login_new2(ss(""));
        if *new != new2.as_str() {
            return toast(&ui, "New login passwords do not match", true);
        }
        match core.profiles.lock().unwrap().change_password(&u.username, &cur, &new) {
            Ok(()) => {
                core.audit().event("profile", "login password changed");
                toast(&ui, "Login password changed", false)
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });

    // ------------------------------------------------------------ vault
    cb!(on_browse_vault, |ui, core, state| {
        if let Some(p) = rfd::FileDialog::new().add_filter("KeePass database", &["kdbx"]).set_title("Open vault").pick_file() {
            ui.global::<Store>().set_vault_path(ss(p.display().to_string()));
        }
    });
    cb!(on_browse_new_vault, |ui, core, state| {
        if let Some(p) = rfd::FileDialog::new().add_filter("KeePass database", &["kdbx"]).set_file_name("LLM Vault.kdbx").set_title("Create vault").save_file() {
            ui.global::<Store>().set_new_vault_path(ss(p.display().to_string()));
        }
    });
    cb!(on_browse_keyfile, |ui, core, state| {
        if let Some(p) = rfd::FileDialog::new().set_title("Key file").pick_file() {
            ui.global::<Store>().set_keyfile_path(ss(p.display().to_string()));
        }
    });
    cb!(on_unlock, |ui, core, state, pw: SharedString| {
        let st = ui.global::<Store>();
        let path = PathBuf::from(st.get_vault_path().trim());
        if path.as_os_str().is_empty() {
            st.set_unlock_error(ss("Choose a vault file first."));
            return;
        }
        let kf = st.get_keyfile_path().trim().to_string();
        let kf = (!kf.is_empty()).then(|| PathBuf::from(kf));
        let pw = Zeroizing::new(pw.to_string());
        st.set_busy(true);
        let r = core.unlock(&path, &pw, kf.as_deref());
        st.set_busy(false);
        match r {
            Ok(()) => {
                if let Some(k) = &kf {
                    let mut s = core.settings.lock().unwrap();
                    s.last_keyfile = Some(k.clone());
                    s.save(&core.paths());
                }
                after_unlock(&ui, core, state);
            }
            Err(e) => st.set_unlock_error(ss(e.to_string())),
        }
    });
    cb!(on_create_vault, |ui, core, state, pw: SharedString, pw2: SharedString| {
        let st = ui.global::<Store>();
        if pw != pw2 {
            st.set_unlock_error(ss("The passwords do not match."));
            return;
        }
        if password_entropy_bits(&pw) < 50.0 {
            st.set_unlock_error(ss("Please use a stronger master password (at least ~50 bits, e.g. 4 random words or 12+ mixed characters)."));
            return;
        }
        let path = PathBuf::from(st.get_new_vault_path().trim());
        let pw = Zeroizing::new(pw.to_string());
        let kf = st.get_keyfile_path().trim().to_string();
        let kf = (!kf.is_empty()).then(|| PathBuf::from(kf));
        if let Some(k) = &kf {
            if !k.exists() {
                st.set_unlock_error(ss("The key file does not exist."));
                return;
            }
        }
        st.set_busy(true);
        let r = core.create_vault(&path, &pw, kf.as_deref());
        st.set_busy(false);
        match r {
            Ok(()) => {
                after_unlock(&ui, core, state);
                toast(&ui, "Vault created. Next: connect a provider and create a client token.", false);
            }
            Err(e) => st.set_unlock_error(ss(e.to_string())),
        }
    });
    cb!(on_lock, |ui, core, state| {
        core.lock("locked by user");
        show_locked(&ui);
    });
    cb!(on_activity, |ui, core, state| {});
    cb!(on_navigate, |ui, core, state, page: i32| {
        ui.global::<Store>().set_page(page);
        refresh_page(&ui, core, state);
    });
    cb!(on_copy_text, |ui, core, state, text: SharedString| {
        copy_plain(&ui, &text);
    });
    cb!(on_open_url, |ui, core, state, url: SharedString| {
        let u = url.trim().to_string();
        if u.starts_with("https://") || u.starts_with("http://") {
            let _ = open::that(u);
        } else {
            toast(&ui, "Only http(s) links can be opened.", true);
        }
    });
    st.on_strength(|pw| (password_entropy_bits(&pw) / 100.0).min(1.0) as f32);
    st.on_strength_label(|pw| {
        if pw.is_empty() {
            return ss("Use a long passphrase - it is the only key to your vault.");
        }
        let bits = password_entropy_bits(&pw);
        let w = match bits {
            b if b < 40.0 => "weak",
            b if b < 60.0 => "fair",
            b if b < 80.0 => "good",
            _ => "strong",
        };
        ss(format!("Strength: {w} (~{bits:.0} bits)"))
    });

    // ------------------------------------------------------------ passwords
    cb!(on_select_group, |ui, core, state, id: SharedString| {
        ui.global::<Store>().set_selected_group(id);
        refresh_passwords(&ui, core, state);
    });
    cb!(on_search_changed, |ui, core, state, _t: SharedString| {
        refresh_passwords(&ui, core, state);
    });
    cb!(on_select_entry, |ui, core, state, id: SharedString| {
        let st = ui.global::<Store>();
        let Some(e) = core.with_vault(|v| v.entry(&id)).flatten() else { return };
        let gidx = state.borrow().group_ids.iter().position(|g| *g == e.group_id).unwrap_or(0);
        st.set_e_id(ss(&e.id));
        st.set_e_title(ss(&e.title));
        st.set_e_username(ss(&e.username));
        st.set_e_password(ss(""));
        st.set_e_password_dirty(false);
        st.set_e_password_visible(false);
        st.set_e_url(ss(&e.url));
        st.set_e_notes(ss(&e.notes));
        st.set_e_tags(ss(&e.tags));
        st.set_e_expires(ss(&e.expires));
        st.set_e_group_index(gidx as i32);
        st.set_e_provider(e.is_provider_key);
        st.set_e_modified(ss(&e.modified));
        st.set_editor_open(true);
    });
    cb!(on_new_entry, |ui, core, state| {
        let st = ui.global::<Store>();
        let sel = st.get_selected_group().to_string();
        let s = state.borrow();
        let gidx = s.group_ids.iter().position(|g| *g == sel).unwrap_or(0);
        st.set_e_id(ss(""));
        st.set_e_title(ss(""));
        st.set_e_username(ss(""));
        st.set_e_password(ss(generate_password(st.get_gen_length() as usize, st.get_gen_upper(), st.get_gen_digits(), st.get_gen_symbols())));
        st.set_e_password_dirty(true);
        st.set_e_password_visible(false);
        st.set_e_url(ss(""));
        st.set_e_notes(ss(""));
        st.set_e_tags(ss(""));
        st.set_e_expires(ss(""));
        st.set_e_group_index(gidx as i32);
        st.set_e_provider(false);
        st.set_e_modified(ss(""));
        st.set_editor_open(true);
    });
    cb!(on_save_entry, |ui, core, state| {
        let st = ui.global::<Store>();
        let expires = st.get_e_expires().trim().to_string();
        let expires = if expires.is_empty() {
            None
        } else {
            match chrono::NaiveDate::parse_from_str(&expires, "%Y-%m-%d") {
                Ok(d) => Some(d),
                Err(_) => return toast(&ui, "Expiry must be YYYY-MM-DD", true),
            }
        };
        let gid = state.borrow().group_ids.get(st.get_e_group_index().max(0) as usize).cloned();
        let id = st.get_e_id().to_string();
        let input = EntryInput {
            id: (!id.is_empty()).then_some(id),
            group_id: gid,
            title: st.get_e_title().to_string(),
            username: st.get_e_username().to_string(),
            password: if st.get_e_password_dirty() || st.get_e_id().is_empty() { Some(Zeroizing::new(st.get_e_password().to_string())) } else { None },
            url: st.get_e_url().to_string(),
            notes: st.get_e_notes().to_string(),
            tags: st.get_e_tags().to_string(),
            expires,
        };
        match core.with_vault_mut(|v| v.upsert_entry(input)) {
            Ok(id) => {
                st.set_e_id(ss(&id));
                st.set_e_password(ss(""));
                st.set_e_password_dirty(false);
                st.set_e_password_visible(false);
                refresh_passwords(&ui, core, state);
                toast(&ui, "Entry saved (vault re-encrypted)", false);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_delete_entry, |ui, core, state, id: SharedString| {
        let title = core.with_vault(|v| v.entry(&id).map(|e| e.title)).flatten().unwrap_or_default();
        confirm(&ui, "Delete entry?", &format!("'{title}' will be removed from the vault. This cannot be undone (a .bak copy of the previous file version is kept)."), "delete-entry", &id, "");
    });
    cb!(on_copy_username, |ui, core, state, id: SharedString| {
        if let Some(e) = core.with_vault(|v| v.entry(&id)).flatten() {
            copy_plain(&ui, &e.username);
        }
    });
    cb!(on_copy_password, |ui, core, state, id: SharedString| {
        let st = ui.global::<Store>();
        if st.get_e_password_dirty() && id == st.get_e_id() && !st.get_e_password().is_empty() {
            return copy_secret(&ui, core, Zeroizing::new(st.get_e_password().to_string()), "Password");
        }
        match core.with_vault(|v| v.entry_password(&id)).flatten() {
            Some(p) if !p.is_empty() => {
                core.audit().event("copy_password", &core.with_vault(|v| v.entry(&id).map(|e| e.title)).flatten().unwrap_or_default());
                copy_secret(&ui, core, p, "Password")
            }
            _ => toast(&ui, "This entry has no password", true),
        }
    });
    cb!(on_reveal_password, |ui, core, state| {
        let st = ui.global::<Store>();
        if st.get_e_password_visible() {
            st.set_e_password_visible(false);
            if !st.get_e_password_dirty() {
                st.set_e_password(ss(""));
            }
            return;
        }
        if !st.get_e_password_dirty() && !st.get_e_id().is_empty() {
            if let Some(p) = core.with_vault(|v| v.entry_password(&st.get_e_id())).flatten() {
                st.set_e_password(ss(p.as_str()));
            }
        }
        st.set_e_password_visible(true);
    });
    cb!(on_generate_password, |ui, core, state| {
        let st = ui.global::<Store>();
        st.set_e_password(ss(generate_password(st.get_gen_length() as usize, st.get_gen_upper(), st.get_gen_digits(), st.get_gen_symbols())));
        st.set_e_password_dirty(true);
        st.set_e_password_visible(true);
    });
    cb!(on_add_group, |ui, core, state, name: SharedString| {
        match core.with_vault_mut(|v| v.add_group(None, &name)) {
            Ok(_) => refresh_passwords(&ui, core, state),
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_rename_group, |ui, core, state, id: SharedString, name: SharedString| {
        match core.with_vault_mut(|v| v.rename_group(&id, &name)) {
            Ok(_) => refresh_passwords(&ui, core, state),
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_delete_group, |ui, core, state, id: SharedString| {
        match core.with_vault_mut(|v| v.delete_group(&id)) {
            Ok(_) => {
                ui.global::<Store>().set_selected_group(ss(""));
                refresh_passwords(&ui, core, state);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });

    // ------------------------------------------------------------ providers
    cb!(on_catalog_changed, |ui, core, state| {
        refresh_providers(&ui, core, state);
    });
    cb!(on_open_preset, |ui, core, state, id: SharedString| {
        let Some(p) = providers::preset(&id) else { return };
        let st = ui.global::<Store>();
        st.set_pd_id(ss(""));
        st.set_pd_preset(ss(p.id));
        st.set_pd_kind(ss(p.kind.as_str()));
        st.set_pd_name(ss(p.name.split(" (").next().unwrap_or(p.name)));
        st.set_pd_base_url(ss(p.base_url));
        st.set_pd_key(ss(""));
        st.set_pd_needs_key(p.needs_key);
        st.set_pd_key_url(ss(p.key_url));
        st.set_pd_api_version(ss(if p.kind == ProviderKind::AzureOpenAi { "2024-10-21" } else { "" }));
        st.set_pd_allow_http(false);
        st.set_pd_examples(ss(p.example_models.join(", ")));
        st.set_provider_dialog(true);
    });
    cb!(on_edit_provider, |ui, core, state, id: SharedString| {
        let Some(p) = core.with_vault(|v| v.config.provider(&id).cloned()).flatten() else { return };
        let preset = providers::preset(&p.preset);
        let st = ui.global::<Store>();
        st.set_pd_id(ss(&p.id));
        st.set_pd_preset(ss(&p.preset));
        st.set_pd_kind(ss(p.kind.as_str()));
        st.set_pd_name(ss(&p.name));
        st.set_pd_base_url(ss(&p.base_url));
        st.set_pd_key(ss(""));
        st.set_pd_needs_key(preset.map(|x| x.needs_key).unwrap_or(false));
        st.set_pd_key_url(ss(preset.map(|x| x.key_url).unwrap_or("")));
        st.set_pd_api_version(ss(p.api_version.clone().unwrap_or_default()));
        st.set_pd_allow_http(p.allow_http);
        st.set_pd_examples(ss(preset.map(|x| x.example_models.join(", ")).unwrap_or_default()));
        st.set_provider_dialog(true);
    });
    cb!(on_save_provider, |ui, core, state| {
        let st = ui.global::<Store>();
        let id = st.get_pd_id().to_string();
        let preset_id = st.get_pd_preset().to_string();
        let preset = providers::preset(&preset_id);
        let name = st.get_pd_name().trim().to_string();
        let base_url = st.get_pd_base_url().trim().trim_end_matches('/').to_string();
        let key = Zeroizing::new(st.get_pd_key().trim().to_string());
        let api_version = st.get_pd_api_version().trim().to_string();
        let allow_http = st.get_pd_allow_http();
        if name.is_empty() {
            return toast(&ui, "Name is required", true);
        }
        let kind = preset.map(|p| p.kind).or_else(|| core.with_vault(|v| v.config.provider(&id).map(|p| p.kind)).flatten()).unwrap_or(ProviderKind::OpenAi);
        let auth = preset.map(|p| p.auth).unwrap_or(AuthStyle::Bearer);
        let mut candidate = ProviderConfig {
            id: if id.is_empty() { new_id() } else { id.clone() },
            name: name.clone(),
            preset: preset_id.clone(),
            kind,
            base_url: base_url.clone(),
            auth,
            secret_entry: None,
            api_version: (!api_version.is_empty()).then_some(api_version),
            allow_http,
            enabled: true,
            created_at: now_rfc3339(),
        };
        if let Err(e) = providers::check_egress(&candidate) {
            return toast(&ui, e.to_string(), true);
        }
        if id.is_empty() && preset.map(|p| p.needs_key).unwrap_or(false) && key.is_empty() {
            return toast(&ui, "This provider needs an API key", true);
        }
        let new_id_ = candidate.id.clone();
        let r = core.with_vault_mut(|v| {
            let existing = v.config.provider(&candidate.id).cloned();
            let secret_entry = existing.as_ref().and_then(|p| p.secret_entry.clone());
            let secret_entry = if !key.is_empty() || (secret_entry.is_some() && existing.as_ref().map(|p| p.name != name).unwrap_or(false)) {
                Some(v.set_provider_secret(secret_entry.as_deref(), &format!("{name} API key"), &base_url, &key)?)
            } else {
                secret_entry
            };
            candidate.secret_entry = secret_entry;
            if candidate.auth != AuthStyle::None && candidate.secret_entry.is_none() && kind == ProviderKind::Ollama {
                candidate.auth = AuthStyle::None;
            }
            match v.config.providers.iter_mut().find(|p| p.id == candidate.id) {
                Some(p) => {
                    candidate.created_at = p.created_at.clone();
                    candidate.enabled = p.enabled;
                    *p = candidate;
                }
                None => v.config.providers.push(candidate),
            }
            v.save()
        });
        drop(key);
        st.set_pd_key(ss(""));
        match r {
            Ok(()) => {
                st.set_provider_dialog(false);
                core.audit().event("provider", &format!("provider '{name}' saved"));
                refresh_providers(&ui, core, state);
                if id.is_empty() {
                    toast(&ui, format!("{name} connected - pick the models you want to expose"), false);
                    run_discovery(&ui, core, new_id_);
                } else {
                    toast(&ui, format!("{name} updated"), false);
                }
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_delete_provider, |ui, core, state, id: SharedString| {
        let name = core.with_vault(|v| v.config.provider(&id).map(|p| p.name.clone())).flatten().unwrap_or_default();
        confirm(&ui, "Remove provider?", &format!("'{name}', its model aliases, prices and its API key entry will be deleted from the vault."), "delete-provider", &id, "");
    });
    cb!(on_toggle_provider, |ui, core, state, id: SharedString, on: bool| {
        let _ = core.with_vault_mut(|v| {
            if let Some(p) = v.config.providers.iter_mut().find(|p| p.id == id.as_str()) {
                p.enabled = on;
            }
            v.save()
        });
        refresh_providers(&ui, core, state);
    });
    cb!(on_test_provider, |ui, core, state, id: SharedString| {
        let Some((up, name)) = upstream_for(core, &id) else { return };
        state.borrow_mut().provider_status.insert(id.to_string(), ("Testing...".into(), true));
        refresh_providers(&ui, core, state);
        let weak = ui.as_weak();
        let c2 = core.clone();
        let st2 = state.clone();
        let id = id.to_string();
        let r = core.rt.block_on(async move { providers::test_connection(&c2.http, &up).await.map_err(|e| c2.redact(&e.to_string())) });
        let (msg, ok) = match r {
            Ok(m) => (m, true),
            Err(e) => (format!("Failed: {e}"), false),
        };
        st2.borrow_mut().provider_status.insert(id, (msg.clone(), ok));
        if let Some(ui) = weak.upgrade() {
            refresh_providers(&ui, core, &st2);
            toast(&ui, format!("{name}: {msg}"), !ok);
        }
    });
    cb!(on_discover_models, |ui, core, state, id: SharedString| {
        run_discovery(&ui, core, id.to_string());
    });
    cb!(on_import_discovered, |ui, core, state| {
        let st = ui.global::<Store>();
        let pid = st.get_discover_provider().to_string();
        let selected: Vec<String> = st.get_discovered().iter().filter(|c| c.checked).map(|c| c.name.to_string()).collect();
        if selected.is_empty() {
            return toast(&ui, "Select at least one model", true);
        }
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let r = core.with_vault_mut(|v| {
            let Some(p) = v.config.provider(&pid).cloned() else { anyhow::bail!("provider not found") };
            let local = matches!(p.preset.as_str(), "ollama-local" | "lmstudio" | "llama-cpp" | "vllm" | "openai-compatible");
            let mut added = 0;
            for m in &selected {
                let mut alias = sanitize_alias(m);
                if p.preset == "ollama-cloud" && !alias.ends_with("-cloud") {
                    alias = format!("{alias}-cloud");
                }
                if v.config.model(&alias).is_some() {
                    alias = format!("{}-{}", alias, sanitize_alias(&p.name));
                }
                if v.config.model(&alias).is_some() {
                    continue;
                }
                v.config.models.push(ModelAlias { alias: alias.clone(), provider_id: pid.clone(), upstream_model: m.clone(), description: format!("{} via {}", m, p.name), enabled: true });
                if local {
                    v.config.prices.push(PriceVersion {
                        id: new_id(),
                        alias,
                        currency: "USD".into(),
                        input: 0.0,
                        output: 0.0,
                        cache_read: 0.0,
                        cache_write: 0.0,
                        reasoning: 0.0,
                        effective_from: today.clone(),
                        source: "local model - no API fee (set an energy/infrastructure estimate if you like)".into(),
                        estimated: true,
                    });
                }
                added += 1;
            }
            v.save()?;
            Ok(added)
        });
        match r {
            Ok(n) => {
                st.set_discover_dialog(false);
                toast(&ui, format!("{n} alias(es) added. Set prices on the Models & pricing page."), false);
                refresh_providers(&ui, core, state);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_detect_local, |ui, core, state| {
        let probes = [
            ("ollama-local", "http://127.0.0.1:11434/api/tags"),
            ("lmstudio", "http://127.0.0.1:1234/v1/models"),
            ("llama-cpp", "http://127.0.0.1:8080/v1/models"),
            ("vllm", "http://127.0.0.1:8000/v1/models"),
        ];
        let http = core.http.clone();
        let found: Vec<&str> = core.rt.block_on(async move {
            let mut f = Vec::new();
            for (id, url) in probes {
                if let Ok(r) = http.get(url).timeout(Duration::from_millis(1500)).send().await {
                    if r.status().is_success() {
                        f.push(id);
                    }
                }
            }
            f
        });
        let existing: Vec<String> = core.with_vault(|v| v.config.providers.iter().map(|p| p.preset.clone()).collect()).unwrap_or_default();
        let mut added = Vec::new();
        for id in found.iter().filter(|id| !existing.iter().any(|e| e == *id)) {
            let p = providers::preset(id).unwrap();
            let cfg = ProviderConfig {
                id: new_id(),
                name: p.name.to_string(),
                preset: p.id.to_string(),
                kind: p.kind,
                base_url: p.base_url.to_string(),
                auth: AuthStyle::None,
                secret_entry: None,
                api_version: None,
                allow_http: false,
                enabled: true,
                created_at: now_rfc3339(),
            };
            let pid = cfg.id.clone();
            if core.with_vault_mut(|v| {
                v.config.providers.push(cfg);
                v.save()
            })
            .is_ok()
            {
                added.push((p.name, pid));
            }
        }
        refresh_providers(&ui, core, state);
        if found.is_empty() {
            toast(&ui, "No local server found (Ollama :11434, LM Studio :1234, llama.cpp :8080, vLLM :8000).", true);
        } else if added.is_empty() {
            toast(&ui, "Local servers found - they are already connected.", false);
        } else {
            toast(&ui, format!("Connected: {}", added.iter().map(|a| a.0).collect::<Vec<_>>().join(", ")), false);
            run_discovery(&ui, core, added[0].1.clone());
        }
    });

    // ------------------------------------------------------------ models & prices
    cb!(on_select_model, |ui, core, state, alias: SharedString| {
        let st = ui.global::<Store>();
        let Some(m) = core.with_vault(|v| v.config.model(&alias).cloned()).flatten() else { return };
        let idx = state.borrow().provider_ids.iter().position(|p| *p == m.provider_id).unwrap_or(0);
        st.set_m_orig_alias(ss(&m.alias));
        st.set_m_alias(ss(&m.alias));
        st.set_m_provider_index(idx as i32);
        st.set_m_upstream(ss(&m.upstream_model));
        st.set_m_description(ss(&m.description));
        st.set_m_enabled(m.enabled);
        st.set_p_effective(ss(chrono::Local::now().format("%Y-%m-%d").to_string()));
        refresh_prices(&ui, core);
    });
    cb!(on_new_model, |ui, core, state| {
        let st = ui.global::<Store>();
        st.set_m_orig_alias(ss(""));
        st.set_m_alias(ss(""));
        st.set_m_upstream(ss(""));
        st.set_m_description(ss(""));
        st.set_m_enabled(true);
        st.set_prices(model(vec![]));
    });
    cb!(on_save_model, |ui, core, state| {
        let st = ui.global::<Store>();
        let orig = st.get_m_orig_alias().to_string();
        let alias = st.get_m_alias().trim().to_string();
        if !valid_alias(&alias) {
            return toast(&ui, "Alias may contain letters, digits and . _ - : / only", true);
        }
        let Some(pid) = state.borrow().provider_ids.get(st.get_m_provider_index().max(0) as usize).cloned() else {
            return toast(&ui, "Connect a provider first", true);
        };
        let upstream = st.get_m_upstream().trim().to_string();
        if upstream.is_empty() {
            return toast(&ui, "Upstream model is required", true);
        }
        let m = ModelAlias { alias: alias.clone(), provider_id: pid, upstream_model: upstream, description: st.get_m_description().to_string(), enabled: st.get_m_enabled() };
        let r = core.with_vault_mut(|v| {
            if alias != orig && v.config.model(&alias).is_some() {
                anyhow::bail!("alias '{alias}' already exists");
            }
            if orig.is_empty() {
                v.config.models.push(m);
            } else if let Some(x) = v.config.models.iter_mut().find(|x| x.alias == orig) {
                *x = m;
                if alias != orig {
                    for p in v.config.prices.iter_mut().filter(|p| p.alias == orig) {
                        p.alias = alias.clone();
                    }
                    for c in v.config.clients.iter_mut() {
                        for a in c.allowed_models.iter_mut().filter(|a| **a == orig) {
                            *a = alias.clone();
                        }
                    }
                }
            }
            v.save()
        });
        match r {
            Ok(()) => {
                st.set_m_orig_alias(ss(&alias));
                if st.get_p_effective().is_empty() {
                    st.set_p_effective(ss(chrono::Local::now().format("%Y-%m-%d").to_string()));
                }
                refresh_models(&ui, core, state);
                toast(&ui, format!("Alias '{alias}' saved"), false);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_delete_model, |ui, core, state, alias: SharedString| {
        confirm(&ui, "Delete alias?", &format!("Clients will no longer be able to call '{alias}'. Its price history is removed too."), "delete-model", &alias, "");
    });
    cb!(on_add_price, |ui, core, state| {
        let st = ui.global::<Store>();
        let alias = st.get_m_orig_alias().to_string();
        let parse = || -> Result<PriceVersion, String> {
            let eff = st.get_p_effective().trim().to_string();
            chrono::NaiveDate::parse_from_str(&eff, "%Y-%m-%d").map_err(|_| "Effective date must be YYYY-MM-DD".to_string())?;
            let cur = st.get_p_currency().trim().to_uppercase();
            if cur.len() != 3 {
                return Err("Currency must be a 3-letter code (USD, EUR, PLN)".into());
            }
            Ok(PriceVersion {
                id: new_id(),
                alias: alias.clone(),
                currency: cur,
                input: parse_f64(&st.get_p_input())?,
                output: parse_f64(&st.get_p_output())?,
                cache_read: parse_f64(&st.get_p_cache_read())?,
                cache_write: parse_f64(&st.get_p_cache_write())?,
                reasoning: parse_f64(&st.get_p_reasoning())?,
                effective_from: eff,
                source: st.get_p_source().trim().to_string(),
                estimated: st.get_p_estimated(),
            })
        };
        match parse() {
            Ok(p) => match core.with_vault_mut(|v| {
                v.config.prices.push(p);
                v.save()
            }) {
                Ok(()) => {
                    refresh_models(&ui, core, state);
                    toast(&ui, "Price version added", false);
                }
                Err(e) => toast(&ui, e.to_string(), true),
            },
            Err(e) => toast(&ui, e, true),
        }
    });
    cb!(on_delete_price, |ui, core, state, id: SharedString| {
        let _ = core.with_vault_mut(|v| {
            v.config.prices.retain(|p| p.id != id.as_str());
            v.save()
        });
        refresh_models(&ui, core, state);
    });

    // ------------------------------------------------------------ clients
    cb!(on_create_client, |ui, core, state| {
        let st = ui.global::<Store>();
        let name = st.get_c_name().trim().to_string();
        if name.is_empty() {
            return toast(&ui, "Give the client a name (e.g. 'VS Code - Code Reviewer')", true);
        }
        let parse = || -> Result<(f64, f64, u32), String> {
            let rpm = st.get_c_rpm().trim().parse::<u32>().map_err(|_| "Requests per minute must be a whole number".to_string());
            Ok((parse_f64(&st.get_c_daily())?, parse_f64(&st.get_c_monthly())?, if st.get_c_rpm().trim().is_empty() { 0 } else { rpm? }))
        };
        let (daily, monthly, rpm) = match parse() {
            Ok(x) => x,
            Err(e) => return toast(&ui, e, true),
        };
        let models: Vec<String> = st.get_c_models().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if let Some(missing) = core.with_vault(|v| models.iter().find(|m| v.config.model(m).is_none()).cloned()).flatten() {
            return toast(&ui, format!("Unknown model alias '{missing}'"), true);
        }
        let ttl_hours: [Option<i64>; 7] = [Some(1), Some(8), Some(24), Some(24 * 7), Some(24 * 30), Some(24 * 90), None];
        let ttl = ttl_hours[st.get_c_ttl_index().clamp(0, 6) as usize];
        let (token, hash, prefix) = new_client_token();
        let client = ClientConfig {
            id: new_id(),
            name: name.clone(),
            project: st.get_c_project().trim().to_string(),
            token_hash: hash,
            token_prefix: prefix,
            allowed_models: models,
            consent_mode: [ConsentMode::Ask, ConsentMode::Session, ConsentMode::Auto][st.get_c_mode_index().clamp(0, 2) as usize],
            expires_at: ttl.map(|h| (chrono::Utc::now() + chrono::Duration::hours(h)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            daily_budget: daily,
            monthly_budget: monthly,
            rpm_limit: rpm,
            revoked: false,
            created_at: now_rfc3339(),
        };
        let cid = client.id.clone();
        match core.with_vault_mut(|v| {
            v.config.clients.push(client);
            v.save()
        }) {
            Ok(()) => {
                core.audit().event("client", &format!("client token created: {name}"));
                st.set_c_name(ss(""));
                st.set_c_project(ss(""));
                refresh_clients(&ui, core);
                show_token(&ui, core, &name, &cid, token);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_revoke_client, |ui, core, state, id: SharedString| {
        let name = core.with_vault(|v| v.config.client(&id).map(|c| c.name.clone())).flatten().unwrap_or_default();
        confirm(&ui, "Revoke token?", &format!("'{name}' will immediately get HTTP 401 for every request."), "revoke-client", &id, "");
    });
    cb!(on_rotate_client, |ui, core, state, id: SharedString| {
        let (token, hash, prefix) = new_client_token();
        let r = core.with_vault_mut(|v| {
            let c = v.config.clients.iter_mut().find(|c| c.id == id.as_str()).ok_or_else(|| anyhow::anyhow!("client not found"))?;
            c.token_hash = hash;
            c.token_prefix = prefix;
            let name = c.name.clone();
            v.save()?;
            Ok(name)
        });
        match r {
            Ok(name) => {
                core.revoke_all_sessions_for(&id);
                core.audit().event("client", &format!("client token rotated: {name}"));
                refresh_clients(&ui, core);
                show_token(&ui, core, &name, &id, token);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_delete_client, |ui, core, state, id: SharedString| {
        let name = core.with_vault(|v| v.config.client(&id).map(|c| c.name.clone())).flatten().unwrap_or_default();
        confirm(&ui, "Delete client?", &format!("'{name}' and its consent rules will be removed. Its audit history is kept."), "delete-client", &id, "");
    });
    cb!(on_snippet_changed, |ui, core, state, idx: i32| {
        let st = ui.global::<Store>();
        // The dialog belongs to the client that was just created/rotated (newest with that name).
        let client_name = st.get_new_token_client().to_string();
        let cid = core.with_vault(|v| v.config.clients.iter().rev().find(|c| c.name == client_name).map(|c| c.id.clone())).flatten().unwrap_or_default();
        st.set_snippet(ss(snippet(idx, &core.gateway_url().unwrap_or_default(), &st.get_new_token(), &models_for(core, &cid))));
    });

    // ------------------------------------------------------------ consents
    cb!(on_decide, |ui, core, state, id: SharedString, d: i32| {
        let decision = match d {
            1 => ConsentDecision::Once,
            2 => ConsentDecision::Session,
            3 => ConsentDecision::Always,
            _ => ConsentDecision::Deny,
        };
        core.resolve_consent(&id, decision);
        refresh_consents(&ui, core);
    });
    cb!(on_revoke_rule, |ui, core, state, kind: SharedString, id: SharedString, model_alias: SharedString| {
        match kind.as_str() {
            "session" => core.revoke_session_grant(&id, &model_alias),
            "always" => {
                let _ = core.with_vault_mut(|v| {
                    v.config.consent_rules.retain(|r| r.id != id.as_str());
                    v.save()
                });
            }
            _ => {
                let _ = core.with_vault_mut(|v| {
                    if let Some(c) = v.config.clients.iter_mut().find(|c| c.id == id.as_str()) {
                        c.consent_mode = ConsentMode::Ask;
                    }
                    v.save()
                });
            }
        }
        core.audit().event("consent", &format!("{kind} grant revoked for {model_alias}"));
        refresh_consents(&ui, core);
        toast(&ui, "Revoked - the next request will ask again", false);
    });

    // ------------------------------------------------------------ activity
    cb!(on_apply_filter, |ui, core, state| {
        refresh_activity(&ui, core, state);
    });
    cb!(on_export_csv, |ui, core, state| {
        let f = activity_filter(&ui, state);
        // --tour recordings export to a fixed path (a file dialog cannot be scripted)
        let tour_path = ui.global::<Store>().get_tour_export_path().to_string();
        let target = if tour_path.is_empty() {
            rfd::FileDialog::new().add_filter("CSV", &["csv"]).set_file_name("llm-vault-usage.csv").save_file()
        } else {
            Some(std::path::PathBuf::from(tour_path))
        };
        if let Some(p) = target {
            match core.audit().export_csv(&f, &p) {
                Ok(n) => toast(&ui, format!("{n} rows exported to {}", p.display()), false),
                Err(e) => toast(&ui, e.to_string(), true),
            }
        }
    });
    cb!(on_export_json, |ui, core, state| {
        let f = activity_filter(&ui, state);
        if let Some(p) = rfd::FileDialog::new().add_filter("JSON", &["json"]).set_file_name("llm-vault-usage.json").save_file() {
            match core.audit().export_json(&f, &p) {
                Ok(n) => toast(&ui, format!("{n} rows exported to {}", p.display()), false),
                Err(e) => toast(&ui, e.to_string(), true),
            }
        }
    });

    // ------------------------------------------------------------ dashboard & settings
    cb!(on_refresh_dashboard, |ui, core, state| {
        refresh_dashboard(&ui, core);
    });
    cb!(on_save_settings, |ui, core, state| {
        let st = ui.global::<Store>();
        let parse = || -> Result<(u16, u64, u32, u32, u32), String> {
            Ok((
                st.get_s_port().trim().parse::<u16>().map_err(|_| "Port must be 1-65535")?,
                st.get_s_consent_timeout().trim().parse::<u64>().map_err(|_| "Consent timeout must be a number of seconds")?.clamp(5, 3600),
                st.get_s_autolock().trim().parse::<u32>().map_err(|_| "Auto-lock must be a number of minutes")?,
                st.get_s_clip().trim().parse::<u32>().map_err(|_| "Clipboard timeout must be a number of seconds")?.clamp(5, 600),
                st.get_s_arm().trim().parse::<u32>().map_err(|_| "Arming delay must be milliseconds")?.clamp(0, 10000),
            ))
        };
        let (port, timeout, autolock, clip, arm) = match parse() {
            Ok(x) => x,
            Err(e) => return toast(&ui, e, true),
        };
        let host = st.get_s_host().trim().to_string();
        if host.parse::<std::net::IpAddr>().is_err() && host != "localhost" {
            return toast(&ui, "Bind address must be an IP address (e.g. 127.0.0.1)", true);
        }
        let currency = ["USD", "EUR", "PLN"][st.get_s_currency_index().clamp(0, 2) as usize].to_string();
        let r = core.with_vault_mut(|v| {
            let restart = v.config.gateway.host != host || v.config.gateway.port != port;
            v.config.gateway.host = host.clone();
            v.config.gateway.port = port;
            v.config.gateway.consent_timeout_s = timeout;
            v.config.security.auto_lock_minutes = autolock;
            v.config.security.clipboard_clear_s = clip;
            v.config.security.consent_arm_ms = arm;
            v.config.display_currency = currency;
            v.save()?;
            Ok(restart)
        });
        match r {
            Ok(restart) => {
                if restart {
                    if let Err(e) = core.restart_gateway() {
                        *core.gateway_error.lock().unwrap() = Some(e.to_string());
                        toast(&ui, format!("Saved, but the gateway could not start: {e}"), true);
                    } else {
                        toast(&ui, "Saved - gateway restarted", false);
                    }
                } else {
                    toast(&ui, "Settings saved", false);
                }
                refresh_settings(&ui, core);
                refresh_header(&ui, core);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_save_fx, |ui, core, state| {
        let st = ui.global::<Store>();
        let cur = st.get_s_fx_currency().trim().to_uppercase();
        let rate = match parse_f64(&st.get_s_fx_rate()) {
            Ok(r) if r > 0.0 => r,
            _ => return toast(&ui, "Rate must be a positive number (units per 1 USD)", true),
        };
        if cur.len() != 3 || cur == "USD" {
            return toast(&ui, "Use a 3-letter currency other than USD", true);
        }
        let date = st.get_s_fx_date().trim().to_string();
        let source = st.get_s_fx_source().trim().to_string();
        let r = core.with_vault_mut(|v| {
            v.config.fx_rates.retain(|r| r.currency != cur);
            v.config.fx_rates.push(FxRate { currency: cur.clone(), per_usd: rate, date, source: if source.is_empty() { "manual".into() } else { source } });
            v.save()
        });
        match r {
            Ok(()) => {
                refresh_settings(&ui, core);
                toast(&ui, format!("Rate for {cur} updated"), false);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_change_password, |ui, core, state| {
        let st = ui.global::<Store>();
        let cur = Zeroizing::new(st.get_pw_current().to_string());
        let new = Zeroizing::new(st.get_pw_new().to_string());
        if *new != st.get_pw_new2().as_str() {
            return toast(&ui, "New passwords do not match", true);
        }
        if password_entropy_bits(&new) < 50.0 {
            return toast(&ui, "Choose a stronger new password", true);
        }
        let r = core.with_vault_mut(|v| v.change_master_password(&cur, &new));
        st.set_pw_current(ss(""));
        st.set_pw_new(ss(""));
        st.set_pw_new2(ss(""));
        match r {
            Ok(()) => {
                core.audit().event("vault", "master password changed");
                toast(&ui, "Master password changed", false);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_import_kdbx, |ui, core, state| {
        let Some(path) = rfd::FileDialog::new().add_filter("KeePass database", &["kdbx"]).set_title("Import KeePass database").pick_file() else { return };
        // The import password is entered in the master-password field of the settings form for simplicity.
        let st = ui.global::<Store>();
        let pw = Zeroizing::new(st.get_pw_current().to_string());
        if pw.is_empty() {
            return toast(&ui, "Type the password of the file to import into 'Current password' first, then click Import again.", true);
        }
        let r = core.with_vault_mut(|v| v.import_kdbx(&path, &pw, None));
        st.set_pw_current(ss(""));
        match r {
            Ok(n) => {
                core.audit().event("vault", &format!("imported {n} entries from {}", path.display()));
                toast(&ui, format!("{n} entries imported into a new group"), false);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });
    cb!(on_export_copy, |ui, core, state| {
        if let Some(p) = rfd::FileDialog::new().add_filter("KeePass database", &["kdbx"]).set_file_name("LLM Vault backup.kdbx").save_file() {
            match core.with_vault(|v| v.export_copy(&p)) {
                Some(Ok(())) => {
                    core.audit().event("vault", &format!("backup copy saved to {}", p.display()));
                    toast(&ui, "Encrypted backup saved (same master password)", false)
                }
                Some(Err(e)) => toast(&ui, e.to_string(), true),
                None => {}
            }
        }
    });
    cb!(on_open_data_dir, |ui, core, state| {
        let _ = std::fs::create_dir_all(&core.paths().data_dir);
        let _ = open::that(&core.paths().data_dir);
    });
    cb!(on_restart_gateway, |ui, core, state| {
        match core.restart_gateway() {
            Ok(u) => toast(&ui, format!("Gateway listening on {u}"), false),
            Err(e) => {
                *core.gateway_error.lock().unwrap() = Some(e.to_string());
                toast(&ui, e.to_string(), true)
            }
        }
        refresh_header(&ui, core);
    });
    cb!(on_confirm_accepted, |ui, core, state| {
        let st = ui.global::<Store>();
        let arg = st.get_confirm_arg().to_string();
        let r: anyhow::Result<&str> = match st.get_confirm_action().as_str() {
            "delete-profile" => core.delete_profile(&arg).map(|_| {
                show_locked(&ui);
                init_welcome(&ui, core);
                "Profile deleted"
            }),
            "delete-entry" => core.with_vault_mut(|v| v.delete_entry(&arg)).map(|_| {
                st.set_editor_open(false);
                st.set_e_id(ss(""));
                "Entry deleted"
            }),
            "delete-provider" => core
                .with_vault_mut(|v| {
                    let p = v.config.provider(&arg).cloned().ok_or_else(|| anyhow::anyhow!("provider not found"))?;
                    let aliases: Vec<String> = v.config.models.iter().filter(|m| m.provider_id == arg).map(|m| m.alias.clone()).collect();
                    v.config.models.retain(|m| m.provider_id != arg);
                    v.config.prices.retain(|x| !aliases.contains(&x.alias));
                    v.config.providers.retain(|x| x.id != arg);
                    v.save()?;
                    if let Some(e) = p.secret_entry {
                        v.delete_entry(&e)?;
                    }
                    Ok(())
                })
                .map(|_| "Provider removed"),
            "delete-model" => core
                .with_vault_mut(|v| {
                    v.config.models.retain(|m| m.alias != arg);
                    v.config.prices.retain(|p| p.alias != arg);
                    v.save()
                })
                .map(|_| {
                    st.set_m_orig_alias(ss(""));
                    st.set_m_alias(ss(""));
                    "Alias deleted"
                }),
            "revoke-client" => core
                .with_vault_mut(|v| {
                    if let Some(c) = v.config.clients.iter_mut().find(|c| c.id == arg) {
                        c.revoked = true;
                    }
                    v.save()
                })
                .map(|_| {
                    core.revoke_all_sessions_for(&arg);
                    core.audit().event("client", "client token revoked");
                    "Token revoked"
                }),
            "delete-client" => core
                .with_vault_mut(|v| {
                    v.config.clients.retain(|c| c.id != arg);
                    v.config.consent_rules.retain(|r| r.client_id != arg);
                    v.save()
                })
                .map(|_| {
                    core.revoke_all_sessions_for(&arg);
                    "Client deleted"
                }),
            _ => Ok(""),
        };
        match r {
            Ok(msg) => {
                if !msg.is_empty() {
                    toast(&ui, msg, false);
                }
                refresh_page(&ui, core, state);
            }
            Err(e) => toast(&ui, e.to_string(), true),
        }
    });

    // ---- startup state (demo / automation)
    if core.is_unlocked() {
        after_unlock(&ui, &core, &state);
    }
    if let Some(p) = opts.page {
        ui.global::<Store>().set_page(p);
        refresh_page(&ui, &core, &state);
    }
    if let Some(idx) = opts.token_snippet {
        let (token, _, _) = llmvault::policy::new_client_token();
        let cid = core.with_vault(|v| v.config.clients.first().map(|c| c.id.clone())).flatten().unwrap_or_default();
        show_token(&ui, &core, "VS Code - Code Reviewer", &cid, token.clone());
        let st = ui.global::<Store>();
        st.set_snippet_index(idx);
        st.set_snippet(ss(snippet(idx, &core.gateway_url().unwrap_or_default(), &token, &models_for(&core, &cid))));
    }
    if let Some(t) = opts.consent_token {
        let c = core.clone();
        slint::Timer::single_shot(Duration::from_millis(600), move || crate::demo::trigger_consent(&c, t));
    }
    if let Some(path) = opts.snapshot {
        ui.window().set_size(slint::LogicalSize::new(1440.0, 900.0));
        let weak = ui.as_weak();
        slint::Timer::single_shot(Duration::from_millis(3500), move || {
            if let Some(ui) = weak.upgrade() {
                match ui.window().take_snapshot() {
                    Ok(buf) => {
                        let img = image::RgbaImage::from_raw(buf.width(), buf.height(), buf.as_bytes().to_vec());
                        if let Some(img) = img {
                            if let Err(e) = img.save(&path) {
                                eprintln!("snapshot failed: {e}");
                            }
                        }
                    }
                    Err(e) => eprintln!("snapshot failed: {e}"),
                }
            }
            let _ = slint::quit_event_loop();
        });
    }

    if let Some((script, out)) = opts.tour {
        crate::tour::start(&ui, core.clone(), script, out);
    }
    let r = ui.run();
    drop(timer);
    core.lock("application closed");
    core.stop_gateway();
    r
}
