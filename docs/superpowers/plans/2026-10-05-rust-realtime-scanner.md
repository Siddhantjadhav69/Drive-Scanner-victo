# Rust Real-Time Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a high-performance, real-time file scanner in Rust that monitors designated directories, scans files against YARA rules, quarantines threats, and alerts the user.

**Architecture:** A multi-threaded producer-consumer system where a `notify` watcher (producer) sends file events via a `crossbeam-channel` to a pool of worker threads. The workers use a cloned `yara` compiler/scanner to check files and execute quarantine/notify actions on matches.

**Tech Stack:** Rust, `notify` (filesystem events), `crossbeam-channel` (queues), `yara-rust` or `yara` (scanning), `notify-rust` (desktop notifications).

**Spec:** docs/superpowers/specs/2026-10-05-rust-realtime-scanner-design.md

## Global Constraints

- Must quarantine files to a `./quarantine/` directory and append `.quarantined`.
- Must log detections to `scanner.log`.
- Must catch and ignore `PermissionDenied` and locking errors gracefully.
- Must compile into a single Rust binary.

---

### Task 1: Project Setup and Base Directories

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`

**Interfaces:**
- Consumes: None
- Produces: Base project structure and dependency definitions.

- [ ] **Step 1: Write Cargo.toml definition**

```toml
[package]
name = "rust-scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
notify = "6.1.1"
crossbeam-channel = "0.5.12"
yara = "0.13.0"
notify-rust = "4.11.0"
chrono = "0.4.38"
```
*(Tests omitted for pure scaffold step)*

- [ ] **Step 2: Create base directories in main**

```rust
use std::fs;

fn setup_directories() -> std::io::Result<()> {
    fs::create_dir_all("rules")?;
    fs::create_dir_all("quarantine")?;
    Ok(())
}

fn main() {
    setup_directories().expect("Failed to create base directories");
    println!("Scanner starting...");
}
```

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml src/main.rs
git commit -m "chore: setup project and base directories"
```

---

### Task 2: Rule Management and Compiler

**Files:**
- Create: `src/rules.rs`
- Modify: `src/main.rs:1-10`

**Interfaces:**
- Consumes: `.yar` files from `rules/`
- Produces: `pub fn compile_rules(dir: &str) -> yara::Compiler`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_compile_rules() {
        std::fs::create_dir_all("test_rules").unwrap();
        let mut file = File::create("test_rules/dummy.yar").unwrap();
        file.write_all(b"rule dummy { condition: true }").unwrap();
        
        let compiler = compile_rules("test_rules");
        assert!(compiler.is_ok());
        std::fs::remove_dir_all("test_rules").unwrap();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test`
Expected: FAIL because `compile_rules` doesn't exist.

- [ ] **Step 3: Write minimal implementation**

```rust
use yara::{Compiler, Error};
use std::fs;
use std::path::Path;

pub fn compile_rules<P: AsRef<Path>>(dir: P) -> Result<Compiler, Error> {
    let mut compiler = Compiler::new()?;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                compiler = compiler.add_rules_file(path)?;
            }
        }
    }
    Ok(compiler)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules.rs src/main.rs
git commit -m "feat: implement YARA rule compilation"
```

---

### Task 3: Scanning and Quarantine Action

**Files:**
- Create: `src/quarantine.rs`
- Create: `src/scanner.rs`
- Modify: `src/main.rs:1-15`

**Interfaces:**
- Consumes: A `yara::Rules` instance.
- Produces: `pub fn scan_and_quarantine(rules: &yara::Rules, filepath: &Path)`

- [ ] **Step 1: Write the failing test for quarantine logic**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;

    #[test]
    fn test_quarantine_action() {
        std::fs::create_dir_all("quarantine").unwrap();
        let test_file = PathBuf::from("test_malware.txt");
        File::create(&test_file).unwrap();
        
        quarantine_file(&test_file).unwrap();
        
        assert!(!test_file.exists());
        let quarantined_path = PathBuf::from("quarantine/test_malware.txt.quarantined");
        assert!(quarantined_path.exists());
        
        std::fs::remove_file(quarantined_path).unwrap();
    }
}
```

- [ ] **Step 2: Write minimal implementation for quarantine**

```rust
use std::path::Path;
use std::fs;
use std::io;

pub fn quarantine_file(filepath: &Path) -> io::Result<()> {
    if let Some(filename) = filepath.file_name() {
        let mut dest = Path::new("quarantine").join(filename);
        dest.set_extension("quarantined");
        fs::rename(filepath, dest)?;
    }
    Ok(())
}
```

- [ ] **Step 3: Implement Scanner Logic**

```rust
use yara::Rules;
use std::path::Path;
use crate::quarantine::quarantine_file;

pub fn scan_path(rules: &Rules, filepath: &Path) {
    // Attempt to scan. Catch permission errors gracefully.
    match rules.scan_file(filepath, 10) {
        Ok(results) => {
            if !results.is_empty() {
                let rule_name = &results[0].identifier;
                println!("Threat detected: {} matched {}", filepath.display(), rule_name);
                let _ = quarantine_file(filepath);
                // In Task 4, we will add logging/notifications here
            }
        },
        Err(e) => {
            println!("Warning: Could not scan {}: {:?}", filepath.display(), e);
        }
    }
}
```

- [ ] **Step 4: Commit**

```bash
git add src/quarantine.rs src/scanner.rs src/main.rs
git commit -m "feat: core scanning and quarantine logic"
```

---

### Task 4: Notifications and Logging

**Files:**
- Create: `src/alert.rs`
- Modify: `src/scanner.rs`

**Interfaces:**
- Produces: `pub fn alert_user(filename: &str, rule_name: &str)` and `pub fn log_event(...)`

- [ ] **Step 1: Write Alert and Log implementations**

```rust
use notify_rust::Notification;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

pub fn alert_user(filename: &str, rule_name: &str) {
    let msg = format!("{} matched rule {} and was quarantined.", filename, rule_name);
    let _ = Notification::new()
        .summary("Threat Detected!")
        .body(&msg)
        .show();
}

pub fn log_event(filepath: &str, rule_name: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("scanner.log") {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(file, "[{}] FILE: {} | RULE: {} | ACTION: Quarantined", now, filepath, rule_name);
    }
}
```

- [ ] **Step 2: Integrate into scanner code**

```rust
// In src/scanner.rs, inside the match rules.scan_file Ok block:
if !results.is_empty() {
    let rule_name = &results[0].identifier;
    if quarantine_file(filepath).is_ok() {
        crate::alert::alert_user(&filepath.display().to_string(), rule_name);
        crate::alert::log_event(&filepath.display().to_string(), rule_name);
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add src/alert.rs src/scanner.rs src/main.rs
git commit -m "feat: desktop notifications and logging"
```

---

### Task 5: File Watcher and Thread Pool (Main Loop)

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `compile_rules`, `scan_path`
- Produces: The main running daemon containing the `notify` watcher and `crossbeam` workers.

- [ ] **Step 1: Implement the multi-threaded watcher system**

```rust
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
```

- [ ] **Step 2: Commit**

```bash
git add src/main.rs
git commit -m "feat: implementation of main watcher and thread pool loop"
```
