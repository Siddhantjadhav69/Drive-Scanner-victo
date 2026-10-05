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
    let yara_rules = std::sync::Arc::new(compiler.compile_rules().expect("Failed to build rule set"));

    let (tx, rx) = unbounded::<PathBuf>();

    // 2. Spawn worker pool (e.g., 4 threads)
    for _ in 0..4 {
        let rx_clone = rx.clone();
        let thread_rules = std::sync::Arc::clone(&yara_rules);

        thread::spawn(move || {
            while let Ok(path) = rx_clone.recv() {
                scanner::scan_path(&thread_rules, &path);
            }
        });
    }

    // 3. Setup watcher
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in event.paths {
                    // Ignore our own compiler artifacts and quarantine folder
                    if let Some(p_str) = path.to_str() {
                        if !p_str.contains("target") && !p_str.contains("quarantine") {
                            let _ = tx.send(path);
                        }
                    }
                }
            }
        }
    }).unwrap();

    // Watch the C drive
    if let Err(e) = watcher.watch(std::path::Path::new("C:\\"), RecursiveMode::Recursive) {
        println!("Warning: Encountered restricted directories while hooking C:\\ -> {:?}", e);
    }

    println!("Scanner running in real-time...");

    // Block main thread
    loop {
        thread::sleep(std::time::Duration::from_secs(60));
    }
}
