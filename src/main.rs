use std::env;
use notify::{Watcher, RecursiveMode, EventKind};
use crossbeam_channel::unbounded;
use std::thread;
use std::path::PathBuf;
use walkdir::WalkDir;
use std::sync::Arc;

mod rules;
mod quarantine;
mod scanner;
mod alert;
mod vss;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "--vss-scan" {
        let drive = &args[2];
        println!("Initiating VSS scan on drive: {}", drive);

        std::fs::create_dir_all("rules").unwrap();
        std::fs::create_dir_all("quarantine").unwrap();

        let compiler = rules::compile_rules("rules").expect("Failed to compile rules");
        let yara_rules = Arc::new(compiler.compile_rules().expect("Failed to build rule set"));

        let snapshot = match vss::VssSnapshot::create(drive) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                println!("Failed to create VSS Snapshot: {:?}", e);
                return;
            }
        };

        println!("Snapshot created at: {}", snapshot.mount_path);

        let (tx, rx) = unbounded::<PathBuf>();

        // Spawn 4 threads for scanning
        let mut handles = vec![];
        for _ in 0..4 {
            let rx_clone = rx.clone();
            let thread_rules = Arc::clone(&yara_rules);
            let thread_snapshot = Arc::clone(&snapshot);

            handles.push(thread::spawn(move || {
                while let Ok(path) = rx_clone.recv() {
                    scanner::scan_path(&thread_rules, &path, Some(&*thread_snapshot));
                }
            }));
        }

        // Walk the directory and push to queue
        for entry in WalkDir::new(&snapshot.mount_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let p = entry.path().to_str().unwrap_or("");
                if !p.contains("quarantine") && !p.contains("target") {
                    let _ = tx.send(entry.into_path());
                }
            }
        }

        // Drop the sender so the receivers know the stream is finished
        drop(tx);

        // Wait for all threads to finish scanning
        for handle in handles {
            let _ = handle.join();
        }

        println!("Scan Complete. VSS Snapshot will now be dropped.");
        return;
    }

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
                scanner::scan_path(&thread_rules, &path, None);
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
