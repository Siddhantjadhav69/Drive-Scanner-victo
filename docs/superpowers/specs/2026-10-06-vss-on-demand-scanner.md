# VSS On-Demand Scanner Design Spec

## Overview
An architectural extension to the existing real-time Rust virus scanner, introducing an On-Demand forensic scanning mode. This mode leverages the Windows Volume Shadow Copy Service (VSS) to create a frozen, point-in-time snapshot of the target drive. Scanning the snapshot entirely bypasses OS-level file locking (e.g., active SQL databases, system registries, locked browser caches), enabling 100% read access without requiring a kernel-mode driver.

## Architecture & Data Flow

### 1. VSS Lifecycle Manager
The manager encapsulates the interactions with native Windows utilities via `std::process::Command`, wrapping them in robust lifecycle hooks to prevent storage leaks.
- **Creation:** Executes `wmic shadowcopy call create Volume="<DriveLetter>\"`. Parses the stdout to extract the newly created `ShadowID`.
- **Resolution:** Executes `vssadmin list shadows` to locate the `ShadowID` and map it to its internal global root device path (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\`).
- **Teardown:** Executes `vssadmin delete shadows /Shadow=<ID> /Quiet`.
- **Safety Guarantee:** The teardown mechanism is bound to the Rust `Drop` trait (and/or a customized Ctrl+C signal handler) to ensure the snapshot is destroyed if the program panics, terminates early, or finishes naturally.

### 2. Execution Pipeline
The new mode reuses the existing producer-consumer architecture, swapping out the producer.
- **The Producer:** Uses the `walkdir` crate to recursively walk the VSS snapshot path. As files are discovered, they are placed onto the existing MPMC `crossbeam` event queue.
- **The Consumers:** The existing Thread Pool (4+ threads carrying cloned YARA engines) pulls from the queue seamlessly. 

### 3. Path Remapping & Action Handling
VSS snapshots are inherently Read-Only. 
- When a file inside the snapshot (e.g., `\\?\GLOBALROOT\Device\...Copy1\Users\siddh\malware.exe`) triggers a YARA detection, the `scan_path` engine must dynamically remap the path back to the active live drive (e.g., `C:\Users\siddh\malware.exe`).
- The quarantine action (move and append `.quarantined`) and the logging action are executed against the *live* drive path. If the active live file is locked, the existing retry loop handles the back-off.

### 4. CLI Integration
- `rust-scanner.exe`: Runs the original real-time `notify` behavior.
- `rust-scanner.exe --vss-scan <DriveLetter>`: Routes to the new On-Demand VSS sweep and terminates upon completion.

## Constraints & Requirements
- Target environment remains Windows-specific (VSS natively tied to NTFS/Windows).
- The scanner MUST be executed with Administrator privileges for the VSS commands to succeed.
