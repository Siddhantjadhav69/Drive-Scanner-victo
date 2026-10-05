use notify::{Watcher, RecursiveMode, EventKind};
use crossbeam_channel::unbounded;
use std::thread;
use std::path::PathBuf;

mod rules;
mod quarantine;
mod scanner;
mod alert;

fn main() {
    // 1. Setup
    std::fs::create_dir_all("rules").unwrap();
    std::fs::create_dir_all("quarantine").unwrap();

    let compiler = rules::compile_rules("rules").expect("Failed to compile rules");
    let yara_rules = compiler.compile_rules().expect("Failed to build rule set");

    let (tx, rx) = unbounded::<PathBuf>();

    // 2. Spawn worker pool (e.g., 4 threads)
    for _ in 0..4 {
        let rx_clone = rx.clone();
        // Rules cannot be shared across threads safely without Arc/Mutex depending on yara bindings,
        // but yara-rust Rules doesn't implement Send + Sync safely out of the box in older versions.
        // For simplicity, we clone the rules or use a wrapper if it supports it. Assuming yara_rules.clone() exists/works.
        // Wait, standard yara Rust bindings allow compiling to a reusable ruleset which often isn't Cloneable.
        // Let's assume we compile per thread or use a globally safe approach.
        // For this plan, we'll compile inside the thread to avoid borrow checker issues for the user.
        let local_compiler = rules::compile_rules("rules").unwrap();
        let local_rules = local_compiler.compile_rules().unwrap();

        thread::spawn(move || {
            while let Ok(path) = rx_clone.recv() {
                scanner::scan_path(&local_rules, &path);
            }
        });
    }

    // 3. Setup watcher
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in event.paths {
                    let _ = tx.send(path);
                }
            }
        }
    }).unwrap();

    // Watch the current directory (for example)
    watcher.watch(std::path::Path::new("."), RecursiveMode::Recursive).unwrap();

    println!("Scanner running in real-time...");

    // Block main thread
    loop {
        thread::sleep(std::time::Duration::from_secs(60));
    }
}
