# ⚡ Sentinel // Cyber Defense Core
### *Ultra-High Performance Forensic VSS & Real-Time Antivirus Engine in Rust*

[![Rust](https://img.shields.io/badge/Language-Rust%202021-orange.svg)](https://www.rust-lang.org/)
[![YARA](https://img.shields.io/badge/Engine-YARA%200.32-blue.svg)](https://virustotal.github.io/yara/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0078d7.svg)](https://microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Sentinel** is an advanced, multi-threaded antivirus and forensic scanning engine written in Rust. It combines industry-standard **YARA pattern matching** with Windows **Volume Shadow Copy Service (VSS)** snapshots, allowing it to bypass OS-level file locking and perform deep, forensic-grade sweeps across entire drives without requiring a kernel-mode driver.

---

## 📸 Cyberpunk Terminal HUD

Sentinel features a custom terminal telemetry dashboard with real-time progress, file inspection, live scan speed calculation, and threat containment feeds:

```text
 ╔══════════════════════════════════════════════════════════════════════════════╗
 ║                ⚡ SENTINEL // CYBER DEFENSE CORE ⚡                          ║
 ║                     [ FORENSIC VSS ENGINE v2.0 ]                             ║
 ╚══════════════════════════════════════════════════════════════════════════════╝
  Target: C:\ | Snapshot: {301AEB28-353C-4788-A569-3588EB91D0EC} | Mode: Zero-Lock Forensic Sweep
 ────────────────────────────────────────────────────────────────────────────────
  [SCANNING] ⠋ Examining: C:\Windows\System32\drivers\etc\hosts

  Progress: [████████████████████░░░░░░░░]  72.4%

  📊 Real-time Telemetry:
    ├─ Files Scanned : 312,450       ├─ Scan Speed : 2,410 files/sec
    ├─ Files Queued  : 431,200       ├─ Elapsed    : 02:14
    └─ Threats Found : 0             └─ Status     : Active (4 Cores)
 ────────────────────────────────────────────────────────────────────────────────
  🛑 THREAT DETECTION FEED:
   [✓] System Integrity Secure. No malicious signatures detected.
 ────────────────────────────────────────────────────────────────────────────────
```

---

## ✨ Key Capabilities

- 🛡️ **Zero-Lock Forensic Sweeps (VSS Integration):** 
  Creates point-in-time frozen volume snapshots (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\`) via PowerShell CIM/WMI to read open SQL databases, registry hives, and locked system caches without collision.
- ⚡ **Multi-Threaded Producer-Consumer Architecture:** 
  Utilizes lock-free crossbeam channels and a scalable worker thread pool to saturate CPU cores for rapid disk traversal and YARA rule execution.
- 🔍 **YARA Detection Engine:** 
  Compiles any number of `.yar` rule files from the `rules/` directory at startup, supporting complex byte sequences, regular expressions, and heuristics.
- 🔄 **Real-Time Active Shield:** 
  Hooks into the Windows kernel filesystem notifications via `notify` to intercept newly created or modified files in milliseconds.
- 🔒 **Safe Live Path Remapping & Quarantine Vault:** 
  When threats are spotted inside read-only VSS snapshots, paths are dynamically remapped back to the live volume (e.g., `C:\`) and isolated into `./quarantine/<filename>.quarantined`.
- 🧯 **Leak-Proof Drop Safety:** 
  Implements the Rust `Drop` trait on the VSS manager to ensure shadow copies are automatically destroyed on completion, panics, or `Ctrl+C`.
- 🤫 **Smart Noise Silencing:** 
  Gracefully identifies and skips 0-byte memory pipes, AF_UNIX domain sockets (Docker/Dart), and restricted DACLs without terminal spam.

---

## 🏗️ Technical Architecture

```text
 ┌──────────────────────────────────────────────────────────────────┐
 │                      SENTINEL SCANNER CORE                       │
 └────────────────────────────────┬─────────────────────────────────┘
                                  │
      ┌───────────────────────────┴───────────────────────────┐
      │                                                       │
  [On-Demand Forensic Mode]                           [Real-Time Shield Mode]
      │                                                       │
  PowerShell CIM / VSS Snapshot                           Kernel FS Watcher
      │                                                       │
  WalkDir Snapshot Producer                              Notify Event Stream
      │                                                       │
      └───────────────────────────┬───────────────────────────┘
                                  │
                     [Lock-Free MPMC Queue]
                     (crossbeam-channel)
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
     [Worker 1]               [Worker 2]               [Worker N]
  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
  │ YARA Engine  │         │ YARA Engine  │         │ YARA Engine  │
  └──────┬───────┘         └──────┬───────┘         └──────┬───────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                         [Threat Detected?]
                                  │
                    YES ──────────┴────────── NO ──> [Next File]
                     │
         ┌───────────┴───────────┐
         │  VSS Path Remapper    │ (Translates snapshot path to live drive)
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         ├─> Quarantine Vault    │ (Moves to ./quarantine/*.quarantined)
         ├─> Desktop Toast Alert │ (notify-rust popup)
         └─> Audit Logger        │ (Appends to scanner.log)
```

---

## 🚀 Quick Start & Installation

### 1. Prerequisites
- **Rust Toolchain:** Install via [rustup.rs](https://rustup.rs/) (Stable 1.70+ recommended).
- **C++ Build Tools:** Required by the `yara` crate's C-bindings (included with Visual Studio or Visual Studio Build Tools).

### 2. Clone the Repository
```bash
git clone https://github.com/<your-username>/rust-scanner.git
cd rust-scanner
```

### 3. Build the Release Binary
```bash
cargo build --release
```

---

## 💻 Usage

> **Note:** Forensic VSS scans require **Administrator Privileges** to command the Windows Volume Shadow Copy service. Open PowerShell or Command Prompt as Administrator.

### Mode 1: On-Demand Zero-Lock Forensic Scan
Perform an exhaustive deep sweep of any drive letter:
```powershell
cargo run --release -- --vss-scan C:\
```
*Or run the compiled executable directly:*
```powershell
.\target\release\rust-scanner.exe --vss-scan C:\
```

### Mode 2: Real-Time Active Shield
Run Sentinel continuously in the background to monitor filesystem changes in real time:
```powershell
cargo run --release
```

---

## 📝 Adding Custom YARA Rules

Sentinel automatically compiles all `.yar` files located in the `rules/` directory at startup. You can drop any custom threat signatures or rules directly into `rules/`:

### Example: `rules/suspicious_powershell.yar`
```yara
rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "Detects obfuscated PowerShell download cradles"
        threat_level = "High"
    strings:
        $bypass = "Set-ExecutionPolicy Bypass" nocase
        $enc = "-EncodedCommand" nocase
        $webclient = "Net.WebClient" nocase
        $iex = "Invoke-Expression" nocase
    condition:
        ($bypass and $enc) or ($webclient and $iex)
}
```

---

## 📂 Project Structure

```text
rust-scanner/
├── Cargo.toml                  # Project configuration and dependencies
├── README.md                   # Documentation and usage guide
├── .gitignore                  # Git ignore rules for builds & quarantine
├── rules/                      # YARA detection rule repository
│   ├── eicar.yar               # Standard AV test signature
│   ├── suspicious_powershell.yar
│   └── ransomware_notes.yar
├── src/
│   ├── main.rs                 # CLI routing, thread orchestrator, and real-time watcher
│   ├── scanner.rs              # Core scanning engine, retry loop, and noise filters
│   ├── vss.rs                  # Windows VSS snapshot manager and Drop trait cleanup
│   ├── stats.rs                # Cyberpunk terminal HUD, metrics, and progress telemetry
│   ├── rules.rs                # Dynamic YARA rule compilation engine
│   ├── quarantine.rs           # Isolation vault handler (.quarantined)
│   └── alert.rs                # Windows desktop notifications and audit logging
└── quarantine/                 # Isolated malware vault (ignored in Git)
```

---

## ❓ FAQ & Troubleshooting

#### Q: Why do some files report "Access is denied"?
**A:** VSS bypasses *File Locks* (files in use by other processes), but respect NTFS permissions (DACLs). Files owned exclusively by `NT AUTHORITY\SYSTEM` or `TrustedInstaller` (e.g. system SAM registry hives) are inaccessible to user-space Admin accounts. Sentinel silences these system files automatically so they do not interrupt your scan.

#### Q: What happens if I interrupt a VSS scan with Ctrl+C?
**A:** Sentinel implements the Rust `Drop` trait on the `VssSnapshot` struct. When the process terminates, the destructor automatically invokes `vssadmin delete shadows` to free up disk space.

---

## 📜 Disclaimer
This software is developed for **authorized security auditing, digital forensics, defensive incident response, and educational research**. Use responsibly.

---

## 📄 License
Distributed under the **MIT License**. See `LICENSE` for details.
