use std::env;
use notify::{Watcher, RecursiveMode, EventKind};
use crossbeam_channel::unbounded;
use std::thread;
use std::path::PathBuf;
use walkdir::WalkDir;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod rules;
mod quarantine;
mod scanner;
mod alert;
mod vss;
mod stats;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "--vss-scan" {
        let drive = &args[2];

        std::fs::create_dir_all("rules").unwrap();
        std::fs::create_dir_all("quarantine").unwrap();

        let compiler = rules::compile_rules("rules").expect("Failed to compile rules");
        let yara_rules = Arc::new(compiler.compile_rules().expect("Failed to build rule set"));

        let snapshot = match vss::VssSnapshot::create(drive) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("Failed to create VSS Snapshot: {:?}", e);
                return;
            }
        };

        let stats = Arc::new(stats::ScanStats::new());
        let is_running = Arc::new(AtomicBool::new(true));

        // Start dynamic terminal HUD
        let ui_handle = stats::start_ui_loop(
            Arc::clone(&stats),
            drive,
            &snapshot.id,
            Arc::clone(&is_running),
        );

        let (tx, rx) = unbounded::<PathBuf>();

        // Spawn 4 high-performance worker threads
        let mut handles = vec![];
        for _ in 0..4 {
            let rx_clone = rx.clone();
            let thread_rules = Arc::clone(&yara_rules);
            let thread_snapshot = Arc::clone(&snapshot);
            let thread_stats = Arc::clone(&stats);

            handles.push(thread::spawn(move || {
                while let Ok(path) = rx_clone.recv() {
                    scanner::scan_path(&thread_rules, &path, Some(&*thread_snapshot), Some(&thread_stats));
                }
            }));
        }

        // Walk snapshot volume and enqueue files
        for entry in WalkDir::new(&snapshot.mount_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let p = entry.path().to_str().unwrap_or("");
                if !p.contains("quarantine") && !p.contains("target") {
                    stats.files_queued.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(entry.into_path());
                }
            }
        }

        // Notify that discovery is finished so progress bar shows real %
        stats.walk_finished.store(true, Ordering::Relaxed);

        // Close channel sender
        drop(tx);

        // Wait for workers to finish scanning all queued files
        for handle in handles {
            let _ = handle.join();
        }

        // Stop UI loop and show final summary
        is_running.store(false, Ordering::Relaxed);
        let _ = ui_handle.join();

        return;
    }

    // --- REAL-TIME WATCHER MODE ---
    std::fs::create_dir_all("rules").unwrap();
    std::fs::create_dir_all("quarantine").unwrap();

    let compiler = rules::compile_rules("rules").expect("Failed to compile rules");
    let yara_rules = std::sync::Arc::new(compiler.compile_rules().expect("Failed to build rule set"));

    let (tx, rx) = unbounded::<PathBuf>();

    // Spawn 4 worker threads for real-time mode
    for _ in 0..4 {
        let rx_clone = rx.clone();
        let thread_rules = std::sync::Arc::clone(&yara_rules);

        thread::spawn(move || {
            while let Ok(path) = rx_clone.recv() {
                scanner::scan_path(&thread_rules, &path, None, None);
            }
        });
    }

    // Setup real-time watcher
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in event.paths {
                    if let Some(p_str) = path.to_str() {
                        if !p_str.contains("target") && !p_str.contains("quarantine") {
                            let _ = tx.send(path);
                        }
                    }
                }
            }
        }
    }).unwrap();

    if let Err(e) = watcher.watch(std::path::Path::new("C:\\"), RecursiveMode::Recursive) {
        eprintln!("Warning: Encountered restricted directories while hooking C:\\ -> {:?}", e);
    }

    println!("⚡ Sentinel real-time defense active on C:\\...");

    loop {
        thread::sleep(std::time::Duration::from_secs(60));
    }
}
