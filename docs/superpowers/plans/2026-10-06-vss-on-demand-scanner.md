# VSS On-Demand Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the real-time virus scanner with an On-Demand scanning mode that uses Windows Volume Shadow Copy (VSS) to completely bypass OS file locks.

**Architecture:** We will create a `vss` module that securely wraps `wmic` and `vssadmin` processes to create, map, and cleanup VSS snapshots. We will parse CLI arguments in `main.rs`: if `--vss-scan` is present, the producer swaps to a `walkdir` recursive iterator that feeds the snapshot files into our existing crossbeam thread pool. Detected paths inside the snapshot are mathematically remapped back to the live C:\ drive for quarantine actions.

**Tech Stack:** Rust, `std::process::Command`, `walkdir`, existing `crossbeam-channel`.

**Spec:** docs/superpowers/specs/2026-10-06-vss-on-demand-scanner.md

## Global Constraints

- Must quarantine files to a `./quarantine/` directory and append `.quarantined`.
- Must log detections to `scanner.log`.
- Must compile into a single Rust binary without cargo testing errors on compilation (tests bypassed if Cargo is not available in environment).
- The teardown mechanism (`vssadmin delete shadows /Shadow=<ID>`) MUST be guaranteed via Rust's `Drop` trait to prevent HDD leakage.

---

### Task 1: Add Dependencies and Basic CLI Structure

**Files:**
- Modify: `Cargo.toml:6-15`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: User command-line arguments.
- Produces: Application exits or diverges logic based on `--vss-scan <Drive>`.

- [ ] **Step 1: Add `walkdir` to Cargo.toml**

```toml
[dependencies]
notify = "6.1.1"
crossbeam-channel = "0.5.12"
yara = { version = "0.32.0", features = ["vendored"] }
notify-rust = "4.11.0"
chrono = "0.4.38"
walkdir = "2.5.0"
```

- [ ] **Step 2: Add CLI parsing to main.rs**

Update `main.rs` to read `std::env::args`. If `--vss-scan <Drive>` is passed, print "VSS Route" and return. Otherwise, run the existing real-time logic.

```rust
use std::env;

// Inside main() before setup:
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "--vss-scan" {
        let drive = &args[2];
        println!("Initiating VSS scan on drive: {}", drive);
        // We will implement VSS integration here in Task 4
        return;
    }
    
    // Existing real-time setup code follows...
```

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml src/main.rs
git commit -m "feat: add walkdir dependency and CLI argument parsing"
```

---

### Task 2: VSS Lifecycle Manager

**Files:**
- Create: `src/vss.rs`
- Modify: `src/main.rs:1-12`

**Interfaces:**
- Produces: `pub struct VssSnapshot { id: String, mount_path: String, drive_letter: String }`
- Produces: `impl VssSnapshot { pub fn create(drive: &str) -> std::io::Result<Self> }`
- Produces: `impl Drop for VssSnapshot`

- [ ] **Step 1: Write VssSnapshot struct and Drop trait**

```rust
use std::process::Command;
use std::io::{Error, ErrorKind};

pub struct VssSnapshot {
    pub id: String,
    pub mount_path: String,
    pub drive_letter: String,
}

impl Drop for VssSnapshot {
    fn drop(&mut self) {
        println!("Cleaning up VSS Snapshot: {}", self.id);
        let _ = Command::new("vssadmin")
            .args(&["delete", "shadows", &format!("/Shadow={}", self.id), "/Quiet"])
            .output();
    }
}
```

- [ ] **Step 2: Write creation logic parsing wmic and vssadmin**

```rust
impl VssSnapshot {
    pub fn create(drive: &str) -> std::io::Result<Self> {
        let wmic_out = Command::new("wmic")
            .args(&["shadowcopy", "call", "create", &format!("Volume=\"{}\"", drive)])
            .output()?;
        
        let output_str = String::from_utf8_lossy(&wmic_out.stdout);
        let mut shadow_id = String::new();
        // Super basic parse, assuming output matches standard wmic format where ShadowID exists
        for line in output_str.lines() {
            if line.contains("ShadowID = ") {
                if let Some(id_part) = line.split('"').nth(1) {
                    shadow_id = id_part.to_string();
                }
            }
        }
        
        if shadow_id.is_empty() {
            return Err(Error::new(ErrorKind::Other, "Failed to extract ShadowID from wmic"));
        }

        let list_out = Command::new("vssadmin")
            .args(&["list", "shadows"])
            .output()?;
        
        let list_str = String::from_utf8_lossy(&list_out.stdout);
        let mut mount_path = String::new();
        let mut found_id = false;
        
        for line in list_str.lines() {
            if line.contains(&shadow_id) {
                found_id = true;
            }
            if found_id && line.contains("Shadow Copy Volume Name:") {
                let parts: Vec<&str> = line.split("Shadow Copy Volume Name:").collect();
                if parts.len() > 1 {
                    mount_path = parts[1].trim().to_string();
                    break;
                }
            }
        }

        if mount_path.is_empty() {
            // Ensure we attempt cleanup gracefully if path resolution fails
            let _ = Command::new("vssadmin")
                .args(&["delete", "shadows", &format!("/Shadow={}", shadow_id), "/Quiet"])
                .output();
            return Err(Error::new(ErrorKind::NotFound, "Failed to find Mount Path in vssadmin"));
        }

        Ok(VssSnapshot {
            id: shadow_id,
            mount_path,
            drive_letter: drive.to_string(),
        })
    }
}
```

- [ ] **Step 3: Register module**
Add `mod vss;` to `main.rs`.

- [ ] **Step 4: Commit**

```bash
git add src/vss.rs src/main.rs
git commit -m "feat: implement VSS lifecycle manager and Drop safety"
```

---

### Task 3: Path Remapping

**Files:**
- Modify: `src/scanner.rs`
- Modify: `src/vss.rs`

**Interfaces:**
- Produces: `pub fn remap_vss_to_live(vss_path: &Path, snapshot: &VssSnapshot) -> PathBuf`

- [ ] **Step 1: Write Remap Function in `vss.rs`**

```rust
use std::path::{Path, PathBuf};

impl VssSnapshot {
    pub fn remap_to_live(&self, vss_path: &Path) -> PathBuf {
        let vss_str = vss_path.to_string_lossy().to_string();
        if vss_str.starts_with(&self.mount_path) {
            let relative = &vss_str[self.mount_path.len()..];
            // E.g., strips `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\`
            // relative becomes `Users\siddh\malware.exe` or `\Users\siddh...`
            let trimmed = relative.trim_start_matches('\\');
            let drive_prefix = self.drive_letter.trim_end_matches('\\'); // e.g. "C:"
            let mut live_path = PathBuf::from(drive_prefix);
            live_path.push("\\");
            live_path.push(trimmed);
            live_path
        } else {
            vss_path.to_path_buf()
        }
    }
}
```

- [ ] **Step 2: Update Scanner Engine**

Modify `scan_path` in `src/scanner.rs` to take an optional `&VssSnapshot` and remap the path for quarantine actions if it is provided. (Note: we must be very careful not to break the real-time mode which passes `None`).

```rust
use crate::vss::VssSnapshot;
// Change signature
pub fn scan_path(rules: &Rules, filepath: &Path, vss: Option<&VssSnapshot>) {
// Inside the `Ok(results) => { if !results.is_empty() {` block...
    let live_filepath = if let Some(snapshot) = vss {
        snapshot.remap_to_live(filepath)
    } else {
        filepath.to_path_buf()
    };
    
    // Replace filepath with &live_filepath for quarantine and alert
    if let Err(e) = quarantine_file(&live_filepath) {
        println!("Warning: Quarantine failed for {}: {:?}", live_filepath.display(), e);
    } else {
        crate::alert::alert_user(&live_filepath.display().to_string(), rule_name);
        crate::alert::log_event(&live_filepath.display().to_string(), rule_name);
    }
```

- [ ] **Step 3: Fix existing tests/invocations**
In `main.rs`, update `scanner::scan_path(&thread_rules, &path);` to `scanner::scan_path(&thread_rules, &path, None);`

- [ ] **Step 4: Commit**

```bash
git add src/scanner.rs src/vss.rs src/main.rs
git commit -m "feat: handle VSS snapshot to live drive path remapping"
```

---

### Task 4: Integrate Walkdir and Trigger Scanner

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `VssSnapshot::create`, `scanner::scan_path`

- [ ] **Step 1: Execute Walkdir producer on CLI Trigger**

In `main.rs`, inside the `--vss-scan` block:

```rust
use walkdir::WalkDir;
use std::sync::Arc;

// Inside main's vss-scan block:
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
                scanner::scan_path(&thread_rules, &path, Some(&thread_snapshot));
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
```

- [ ] **Step 2: Commit**

```bash
git add src/main.rs
git commit -m "feat: implement VSS walkdir traversal and consumer pool"
```
