# Real-Time Virus Scanner Design Spec

## Overview
A high-performance, real-time file scanner built in Rust. The scanner acts as a host-based intrusion detection/prevention system, similar to Malwarebytes. It continually monitors designated directories for new or modified files and scans them against a set of predefined YARA rules. If a threat is detected, it neutralizes it by quarantining the file and alerts the user via a native desktop notification.

## Architecture & Data Flow

The system uses a multi-threaded producer-consumer architecture to ensure the filesystem watcher doesn't block during scanning.

1. **The Watcher (Producer):** Uses the `notify` crate to hook into OS-level filesystem events. It listens for `Create` and `Modify` events.
2. **Event Queue:** When a file event occurs, the file path is pushed to a fast, thread-safe Multi-Producer Multi-Consumer (MPMC) channel (e.g., `crossbeam-channel` or `std::sync::mpsc`).
3. **Thread Pool (Consumers):** A pool of background worker threads constantly polls the queue. Each thread holds a cloned reference to the compiled YARA scanner.
4. **Scanning Engine:** Uses the `yara-rust` bindings. Worker threads pull a file path, load the file into memory, and scan it against the active YARA rules.

## Core Components

### 1. Rule Management
- **Directory:** `./rules/`
- **Behavior:** On startup, the main thread reads all `.yar` files in the directory.
- **Compilation:** The rules are compiled into a unified YARA compiler instance, which is then instantiated into a scanner. Clones of this scanner are passed to the worker pool.

### 2. Detection & Quarantine Action
When a file matches a YARA rule:
- **Quarantine:** The scanner takes immediate action to move the offending file from its original location to an isolated `./quarantine/` directory.
- **Neutralization:** The file is renamed to include a `.quarantined` extension to prevent accidental execution.
- **Logging:** A persistent log entry is written to `scanner.log`, recording the timestamp, original path, quarantine path, and the matched YARA rule name.

### 3. Notifications
- **Trigger:** Immediately following a successful quarantine.
- **Provider:** Uses the `notify-rust` crate to send a Windows native desktop snippet.
- **Message:** "Threat Detected! [Filename] matched rule [Rule Name] and was quarantined."

### 4. Error Handling & Edge Cases
- **Permission Denied / File Locks:** Windows heavily utilizes file locking. The scanning thread will gracefully catch `std::io::Error` instances (especially `PermissionDenied` and file-in-use errors). Instead of crashing, the thread will log a warning and proceed to the next event in the queue.
- **Queue Overload:** The channel will be properly sized or unbound, and the thread pool will scale based on logical CPU cores to ensure fast processing even during bulk file operations (e.g., extracting an archive).

## Scope & Future Work
- The initial development (this spec) focuses on scanning predefined folders, alerting, and basic quarantine.
- **Out of Scope (for now):** Memory/process scanning, heuristic/behavioral analysis, and a graphical user interface (GUI).
