//! `--tour <script.json> --record <out.mp4>`: drives the real UI through a scripted sequence (navigation,
//! typing, creating a client token, live gateway requests, consent decisions) and records the window
//! frame by frame with `take_snapshot`, piped into ffmpeg. Used for the product videos only - it needs
//! `--demo`, so it never touches real vaults. A JSON log with the time of every step and every HTTP
//! exchange is written next to the video so the edit can sync captions, cursor and terminal to it.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use slint::{ComponentHandle, Model, SharedString};

use llmvault::core::Core;

use crate::{AppWindow, Store};

#[derive(Deserialize, Clone)]
struct Step {
    at: u64,
    #[serde(rename = "do")]
    action: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    field: String,
    #[serde(default)]
    n: i32,
    #[serde(default = "default_cps")]
    cps: f64,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    body: Value,
    #[serde(default)]
    agent: String,
    #[serde(default)]
    id: String,
    /// `exec`: program + arguments, run with VAULT_CLIENT_TOKEN / LLMVAULT_URL (the token created in the tour)
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    cwd: String,
}

fn default_cps() -> f64 {
    14.0
}

#[derive(Deserialize)]
struct Script {
    #[serde(default = "default_fps")]
    fps: u32,
    #[serde(default = "default_size")]
    size: [f32; 2],
    steps: Vec<Step>,
}

fn default_fps() -> u32 {
    30
}

fn default_size() -> [f32; 2] {
    [1440.0, 900.0]
}

struct Recorder {
    tx: std::sync::mpsc::SyncSender<(u64, Vec<u8>)>,
    size: (u32, u32),
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Recorder {
    fn start(out: PathBuf, w: u32, h: u32, fps: u32) -> std::io::Result<Recorder> {
        let mut child = std::process::Command::new("ffmpeg")
            .args(["-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgba", "-s", &format!("{w}x{h}"), "-r", &fps.to_string(), "-i", "-"])
            .args(["-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2", "-c:v", "libx264", "-preset", "ultrafast", "-crf", "10", "-pix_fmt", "yuv420p"])
            .arg(&out)
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<(u64, Vec<u8>)>(150);
        let worker = std::thread::spawn(move || {
            let mut stdin = child.stdin.take().expect("ffmpeg stdin");
            let mut written: u64 = 0;
            let mut last: Option<Vec<u8>> = None;
            for (idx, frame) in rx {
                // Snapshots are not exactly periodic: repeat the previous frame to stay on wall-clock time.
                while written < idx {
                    if let Some(prev) = &last {
                        let _ = stdin.write_all(prev);
                    } else {
                        let _ = stdin.write_all(&frame);
                    }
                    written += 1;
                }
                let _ = stdin.write_all(&frame);
                written += 1;
                last = Some(frame);
            }
            drop(stdin);
            let _ = child.wait();
        });
        Ok(Recorder { tx, size: (w, h), worker: Some(worker) })
    }

    fn finish(mut self) {
        drop(self.tx);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

/// Starts the tour. Returns immediately; the timers own everything and quit the event loop at the end.
pub fn start(ui: &AppWindow, core: Arc<Core>, script_path: PathBuf, out: PathBuf) {
    let script: Script = match std::fs::read_to_string(&script_path).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string())) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tour script {}: {e}", script_path.display());
            return;
        }
    };
    ui.window().set_size(slint::LogicalSize::new(script.size[0], script.size[1]));
    let fps = script.fps.max(1);
    let log: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let token: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let recorder: Rc<RefCell<Option<Recorder>>> = Rc::new(RefCell::new(None));
    let steps = Rc::new(RefCell::new(expand(script.steps)));
    let weak = ui.as_weak();
    // Lives for the rest of the process (the tour ends by quitting the event loop).
    let timer: &'static slint::Timer = Box::leak(Box::new(slint::Timer::default()));
    let last_idx = Rc::new(std::cell::Cell::new(-1i64));
    let t0: Rc<RefCell<Option<Instant>>> = Rc::new(RefCell::new(None));
    let end_at = Rc::new(RefCell::new(None::<u64>));

    // Give the window a moment to appear and lay out before the clock starts.
    slint::Timer::single_shot(Duration::from_millis(1500), move || {
        timer.start(slint::TimerMode::Repeated, Duration::from_millis(1000 / fps as u64 / 2), move || {
            let Some(ui) = weak.upgrade() else { return };
            let start = *t0.borrow_mut().get_or_insert_with(Instant::now);
            let now_ms = start.elapsed().as_millis() as u64;

            // ---- due steps
            loop {
                let next = steps.borrow().first().cloned();
                let Some(step) = next else { break };
                if step.at > now_ms {
                    break;
                }
                steps.borrow_mut().remove(0);
                if !step.action.starts_with('_') {
                    log.lock().unwrap().push(json!({"t": now_ms, "kind": "step", "do": step.action, "field": step.field, "text": step.text, "n": step.n, "id": step.id}));
                }
                run_step(&ui, &core, &step, now_ms, &start, &log, &token, &end_at);
            }

            // ---- frame capture (once per output frame index)
            let idx = (now_ms * fps as u64 / 1000) as i64;
            let fresh = idx != last_idx.get();
            last_idx.set(idx);
            if !fresh {
            } else if let Ok(buf) = ui.window().take_snapshot() {
                let (w, h) = (buf.width(), buf.height());
                let mut rec = recorder.borrow_mut();
                if rec.is_none() {
                    match Recorder::start(out.clone(), w, h, fps) {
                        Ok(r) => *rec = Some(r),
                        Err(e) => {
                            eprintln!("cannot start ffmpeg: {e}");
                            let _ = slint::quit_event_loop();
                            return;
                        }
                    }
                }
                if let Some(r) = rec.as_ref() {
                    let bytes = buf.as_bytes().to_vec();
                    if r.size == (w, h) {
                        let _ = r.tx.send((idx as u64, bytes));
                    } else if let Some(img) = image::RgbaImage::from_raw(w, h, bytes) {
                        // The OS may clamp a window taller than the screen (e.g. after unlock): keep the stream size.
                        let fit = image::imageops::resize(&img, r.size.0, r.size.1, image::imageops::FilterType::Triangle);
                        let _ = r.tx.send((idx as u64, fit.into_raw()));
                    }
                }
            }

            if let Some(end) = *end_at.borrow() {
                if now_ms >= end {
                    if let Some(r) = recorder.borrow_mut().take() {
                        r.finish();
                    }
                    let entries = log.lock().unwrap().clone();
                    let meta = json!({"fps": fps, "duration_ms": now_ms, "events": entries});
                    let _ = std::fs::write(out.with_extension("json"), serde_json::to_string_pretty(&meta).unwrap_or_default());
                    let _ = slint::quit_event_loop();
                }
            }
        });
    });
}

/// Typing steps become one internal step per character so they show up as real keystrokes.
fn expand(steps: Vec<Step>) -> Vec<Step> {
    let mut out = Vec::new();
    for s in steps {
        if s.action == "type" || s.action == "type_pw" {
            let mut typed = String::new();
            let gap = (1000.0 / s.cps.max(1.0)) as u64;
            for (i, ch) in s.text.chars().enumerate() {
                typed.push(ch);
                let mut c = s.clone();
                c.at = s.at + i as u64 * gap;
                c.action = if i == 0 { s.action.clone() } else { format!("_{}", s.action) };
                c.text = typed.clone();
                out.push(c);
            }
        } else {
            out.push(s);
        }
    }
    out.sort_by_key(|s| s.at);
    out
}

fn set_field(st: &Store, field: &str, v: &str) {
    let v = SharedString::from(v);
    match field {
        "c-name" => st.set_c_name(v),
        "c-project" => st.set_c_project(v),
        "c-models" => st.set_c_models(v),
        "c-daily" => st.set_c_daily(v),
        "c-monthly" => st.set_c_monthly(v),
        "c-rpm" => st.set_c_rpm(v),
        "search" => st.set_search(v),
        "m-upstream" => st.set_m_upstream(v),
        other => eprintln!("tour: unknown field {other}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_step(ui: &AppWindow, core: &Arc<Core>, s: &Step, now_ms: u64, start: &Instant, log: &Arc<Mutex<Vec<Value>>>, token: &Arc<Mutex<String>>, end_at: &Rc<RefCell<Option<u64>>>) {
    let st = ui.global::<Store>();
    match s.action.trim_start_matches('_') {
        "lock" => st.invoke_lock(),
        "type_pw" => st.set_tour_pw(SharedString::from(s.text.as_str())),
        "unlock" => {
            st.set_tour_pw(SharedString::from(""));
            st.invoke_unlock(SharedString::from(crate::demo::DEMO_PASSWORD));
        }
        "page" => st.invoke_navigate(s.n),
        "type" => set_field(&st, &s.field, &s.text),
        "mode" => st.set_c_mode_index(s.n),
        "ttl" => st.set_c_ttl_index(s.n),
        "create_client" => {
            st.invoke_create_client();
            *token.lock().unwrap() = st.get_new_token().to_string();
        }
        "snippet" => {
            st.set_snippet_index(s.n);
            st.invoke_snippet_changed(s.n);
        }
        "close_token" => {
            st.set_token_dialog(false);
            st.set_new_token(SharedString::from(""));
        }
        "decide" => {
            if let Some(c) = st.get_pending().row_data(0) {
                st.invoke_decide(c.id, s.n);
            }
        }
        "http" => {
            let url = format!("{}{}", core.gateway_url().unwrap_or_else(|| "http://127.0.0.1:8799/v1".into()), s.path);
            let tok = token.lock().unwrap().clone();
            let (method, body, agent, id) = (s.method.clone(), s.body.clone(), s.agent.clone(), s.id.clone());
            let log = log.clone();
            let start = *start;
            log.lock().unwrap().push(json!({"t": now_ms, "kind": "http_start", "id": id, "method": method, "url": url, "body": body}));
            core.rt.spawn(async move {
                let http = reqwest::Client::new();
                let mut rq = if method == "GET" { http.get(&url) } else { http.post(&url).json(&body) };
                if !tok.is_empty() {
                    rq = rq.bearer_auth(&tok);
                }
                if !agent.is_empty() {
                    rq = rq.header("X-LLMVault-Agent", agent);
                }
                let t1 = Instant::now();
                let (status, text) = match rq.send().await {
                    Ok(r) => {
                        let code = r.status().as_u16();
                        (code, r.text().await.unwrap_or_default())
                    }
                    Err(e) => (0, e.to_string()),
                };
                let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
                log.lock().unwrap().push(json!({
                    "t": start.elapsed().as_millis() as u64, "kind": "http_end", "id": id, "status": status,
                    "elapsed_ms": t1.elapsed().as_millis() as u64, "response": parsed
                }));
            });
        }
        "exec" => exec(core, s, now_ms, start, log, token),
        // model alias editor: open an alias, point it at another provider (index in the provider list), save
        "select_model" => st.invoke_select_model(SharedString::from(s.text.as_str())),
        "model_provider" => st.set_m_provider_index(s.n),
        "save_model" => st.invoke_save_model(),
        // activity page: filter by a client name, export the filtered rows (CSV) to `text`
        "filter_client" => {
            let clients = st.get_f_clients();
            match (0..clients.row_count()).find(|&i| clients.row_data(i).is_some_and(|c| c == s.text.as_str())) {
                Some(i) => {
                    st.set_f_client(i as i32);
                    st.invoke_apply_filter();
                }
                None => eprintln!("tour: filter_client - no client {}", s.text),
            }
        }
        "export_csv" => {
            st.set_tour_export_path(SharedString::from(s.text.as_str()));
            st.invoke_export_csv();
        }
        "revoke_new" => {
            // the client created in this tour (newest with the dialog's name), revoked like the Revoke button does
            let name = st.get_new_token_client().to_string();
            let id = core.with_vault(|v| v.config.clients.iter().rev().find(|c| c.name == name).map(|c| c.id.clone())).flatten();
            match id {
                Some(id) => {
                    // the Revoke button asks for confirmation first; the dialog is visible for 0.6 s, then the tour
                    // confirms and closes it like a click on "Confirm"
                    st.invoke_revoke_client(SharedString::from(id));
                    let weak = ui.as_weak();
                    slint::Timer::single_shot(Duration::from_millis(600), move || {
                        if let Some(ui) = weak.upgrade() {
                            let st = ui.global::<Store>();
                            st.invoke_confirm_accepted();
                            st.set_confirm_open(false);
                        }
                    });
                }
                None => eprintln!("tour: revoke_new - no client named {name}"),
            }
        }
        "toast" => st.set_toast(SharedString::from(s.text.as_str())),
        "end" => *end_at.borrow_mut() = Some(now_ms),
        other => eprintln!("tour: unknown step {other}"),
    }
}

/// Runs a real program (a demo script) with the token created in the tour and logs every line of its output with the
/// tour clock, so the edit can replay the terminal exactly as it happened.
fn exec(core: &Arc<Core>, s: &Step, now_ms: u64, start: &Instant, log: &Arc<Mutex<Vec<Value>>>, token: &Arc<Mutex<String>>) {
    let Some((prog, args)) = s.cmd.split_first() else {
        eprintln!("tour: exec without cmd");
        return;
    };
    let base = core.gateway_url().unwrap_or_else(|| "http://127.0.0.1:8799/v1".into());
    let tok = token.lock().unwrap().clone();
    // ${VAULT_CLIENT_TOKEN} / ${LLMVAULT_URL} in arguments, for programs that take them on the command line (curl.exe)
    let args: Vec<String> = args.iter().map(|a| a.replace("${VAULT_CLIENT_TOKEN}", &tok).replace("${LLMVAULT_URL}", &base)).collect();
    let mut cmd = std::process::Command::new(prog);
    cmd.args(&args)
        .env("VAULT_CLIENT_TOKEN", token.lock().unwrap().clone())
        .env("LLMVAULT_URL", &base)
        .env("PYTHONUNBUFFERED", "1")
        .env("PYTHONUTF8", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if !s.cwd.is_empty() {
        cmd.current_dir(&s.cwd);
    }
    let id = s.id.clone();
    log.lock().unwrap().push(json!({"t": now_ms, "kind": "exec_start", "id": id, "cmd": s.cmd}));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log.lock().unwrap().push(json!({"t": now_ms, "kind": "exec_end", "id": id, "code": -1, "error": e.to_string()}));
            return;
        }
    };
    let start = *start;
    let pipe = |r: Box<dyn std::io::Read + Send>, stream: &'static str, log: Arc<Mutex<Vec<Value>>>, id: String| {
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(r).lines().map_while(Result::ok) {
                log.lock().unwrap().push(json!({"t": start.elapsed().as_millis() as u64, "kind": stream, "id": id, "line": line}));
            }
        })
    };
    let out = pipe(Box::new(child.stdout.take().expect("stdout")), "stdout", log.clone(), id.clone());
    let err = pipe(Box::new(child.stderr.take().expect("stderr")), "stderr", log.clone(), id.clone());
    let log = log.clone();
    std::thread::spawn(move || {
        let code = child.wait().map(|st| st.code().unwrap_or(-1)).unwrap_or(-1);
        let _ = out.join();
        let _ = err.join();
        log.lock().unwrap().push(json!({"t": start.elapsed().as_millis() as u64, "kind": "exec_end", "id": id, "code": code}));
    });
}
