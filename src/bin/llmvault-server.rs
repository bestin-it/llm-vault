//! Headless gateway for the strong-isolation deployment mode: run it on a separate VM, under a
//! separate OS account or on another device that AI agents cannot access. There is no UI, so
//! interactive consent is not available: only pre-approved clients and standing consent rules
//! are served (configure them in the desktop app, then copy the .kdbx file to the server).
//!
//! Usage: llmvault-server --vault /path/LLM Vault.kdbx [--keyfile key.keyx] [--host 0.0.0.0] [--port 8765]
//! The master password is read from the terminal, or from LLMVAULT_PASSWORD_FILE (a file readable
//! only by the service account) for unattended start.

use std::path::PathBuf;

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    if std::env::args().any(|a| a == "--help" || a == "-h") || arg("--vault").is_none() {
        eprintln!("LLM Vault headless gateway {}\n\nUsage: llmvault-server --vault <file.kdbx> [--keyfile <file>] [--host <ip>] [--port <n>]\n\nEnv: LLMVAULT_PASSWORD_FILE=<path>  read the master password from a protected file", env!("CARGO_PKG_VERSION"));
        std::process::exit(2);
    }
    let vault = PathBuf::from(arg("--vault").unwrap());
    let keyfile = arg("--keyfile").map(PathBuf::from);
    let password = match std::env::var("LLMVAULT_PASSWORD_FILE") {
        Ok(f) => zeroize::Zeroizing::new(std::fs::read_to_string(f).expect("cannot read password file").trim_end_matches(['\r', '\n']).to_string()),
        Err(_) => zeroize::Zeroizing::new(rpassword::prompt_password("Master password: ").expect("cannot read password")),
    };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    let core = llmvault::core::Core::new(llmvault::paths::Paths::detect(), rt.handle().clone()).expect("core");
    {
        let c = core.clone();
        core.set_notifier(move |ev| match ev {
            llmvault::core::UiEvent::ConsentRequested(info) => {
                eprintln!("[consent] {} / {} -> {} denied: interactive consent is not available in headless mode", info.client_name, info.agent, info.model_alias);
                c.resolve_consent(&info.id, llmvault::policy::ConsentDecision::Deny);
            }
            llmvault::core::UiEvent::Locked(r) => eprintln!("[vault] locked: {r}"),
            _ => {}
        });
    }
    if let Err(e) = core.unlock(&vault, &password, keyfile.as_deref()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    drop(password);
    // Optional bind override for the server deployment.
    if arg("--host").is_some() || arg("--port").is_some() {
        let r = core.with_vault_mut(|v| {
            if let Some(h) = arg("--host") {
                v.config.gateway.host = h;
            }
            if let Some(p) = arg("--port") {
                v.config.gateway.port = p.parse()?;
            }
            Ok(())
        });
        if let Err(e) = r {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
        core.stop_gateway();
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Err(e) = core.start_gateway() {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    match core.gateway_url() {
        Some(u) => eprintln!("LLM Vault gateway listening on {u} (Ctrl+C to stop)"),
        None => {
            eprintln!("error: gateway did not start: {}", core.gateway_error.lock().unwrap().clone().unwrap_or_default());
            std::process::exit(1);
        }
    }
    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    core.lock("server stopped");
    core.stop_gateway();
}
