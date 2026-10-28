fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-light".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI compilation failed");

    // Embed the application icon and version info into the Windows executable.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/llmvault.ico");
        res.set("ProductName", "LLM Vault");
        res.set("FileDescription", "LLM Vault - password manager with a secure LLM gateway");
        res.set("CompanyName", "bestin-it.com");
        res.set("LegalCopyright", "Apache-2.0 - bestin-it.com");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed Windows resources: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/llmvault.ico");
}
