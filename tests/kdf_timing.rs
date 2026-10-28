//! Timing of vault create / unlock / save with the production Argon2id parameters.
//!   cargo test --release --test kdf_timing -- --ignored --nocapture
use std::time::Instant;

use llmvault::vault::{EntryInput, KdfStrength, Vault};

#[test]
#[ignore]
fn kdf_timing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("timing.kdbx");
    let t = Instant::now();
    let mut v = Vault::create(&path, "timing-test-password", None, KdfStrength::Standard).unwrap();
    let create = t.elapsed();
    for i in 0..200 {
        v.upsert_entry(EntryInput { title: format!("entry {i}"), username: "user".into(), password: Some(zeroize::Zeroizing::new("p@ss-word-123".into())), ..Default::default() })
            .unwrap();
    }
    let t = Instant::now();
    v.save().unwrap();
    let save = t.elapsed();
    drop(v);
    let mut unlock = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let _v = Vault::open(&path, "timing-test-password", None).unwrap();
        unlock.push(t.elapsed().as_millis());
    }
    let t = Instant::now();
    assert!(Vault::open(&path, "wrong-password", None).is_err());
    let wrong = t.elapsed();
    let size = std::fs::metadata(&path).unwrap().len();
    println!("create: {} ms, save (200 entries): {} ms, unlock x5: {:?} ms, wrong password rejected after {} ms, file {} bytes",
        create.as_millis(), save.as_millis(), unlock, wrong.as_millis(), size);
}
