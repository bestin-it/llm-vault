//! LLM Vault desktop application.
#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

mod demo;
mod tour;
mod ui;

slint::include_modules!();

fn main() {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("LLM Vault {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(4).thread_name("llmvault-gw").build().expect("tokio runtime");
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned());
    let demo = args.iter().any(|a| a == "--demo");
    let paths = if demo {
        // Isolated throw-away location: the demo never touches real vaults or settings.
        let dir = std::env::temp_dir().join("llmvault-demo");
        let _ = std::fs::remove_dir_all(&dir);
        llmvault::paths::Paths::for_dir(&dir)
    } else {
        llmvault::paths::Paths::detect()
    };
    let core = match llmvault::core::Core::new(paths, rt.handle().clone()) {
        Ok(c) => c,
        Err(e) => {
            let _ = rfd::MessageDialog::new().set_title("LLM Vault").set_description(format!("Cannot start LLM Vault: {e}")).set_level(rfd::MessageLevel::Error).show();
            return;
        }
    };
    let mut opts = ui::LaunchOptions {
        page: arg("--page").and_then(|p| p.parse().ok()),
        snapshot: arg("--snapshot").map(std::path::PathBuf::from),
        consent_token: None,
        token_snippet: arg("--token-snippet").and_then(|p| p.parse().ok()),
        tour: None,
    };
    if demo {
        if let (Some(script), Some(out)) = (arg("--tour"), arg("--record")) {
            opts.tour = Some((script.into(), out.into()));
        }
    }
    if demo {
        if let Err(e) = core.register("demo", "Demo User", demo::DEMO_PASSWORD) {
            eprintln!("demo profile failed: {e}");
        }
        match demo::setup(&core) {
            Ok(d) => {
                if args.iter().any(|a| a == "--consent") {
                    opts.consent_token = Some(d.ask_token);
                }
            }
            Err(e) => eprintln!("demo setup failed: {e}"),
        }
    }
    if let Err(e) = ui::run(core, opts) {
        let _ = rfd::MessageDialog::new().set_title("LLM Vault").set_description(format!("Window system error: {e}")).set_level(rfd::MessageLevel::Error).show();
    }
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
}
