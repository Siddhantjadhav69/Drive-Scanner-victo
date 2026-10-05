use yara::Rules;
use std::path::Path;
use crate::quarantine::quarantine_file;
use std::thread;
use std::time::Duration;
use crate::vss::VssSnapshot;
use crate::stats::ScanStats;
use std::sync::Arc;

pub fn scan_path(rules: &Rules, filepath: &Path, vss: Option<&VssSnapshot>, stats: Option<&Arc<ScanStats>>) {
    if !filepath.is_file() {
        return;
    }

    if let Some(s) = stats {
        if let Ok(mut cur) = s.current_file.try_lock() {
            let display_path = if let Some(snapshot) = vss {
                snapshot.remap_to_live(filepath).to_string_lossy().to_string()
            } else {
                filepath.to_string_lossy().to_string()
            };
            *cur = display_path;
        }
    }

    // Skip 0-byte files, symlinks, and sockets
    match std::fs::symlink_metadata(filepath) {
        Ok(meta) => {
            if meta.len() == 0 {
                if let Some(s) = stats {
                    s.files_scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return;
            }
        },
        Err(_) => {
            if let Some(s) = stats {
                s.files_scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
    }

    let mut attempts = 0;
    let max_attempts = 3;

    while attempts < max_attempts {
        match rules.scan_file(filepath, 10) {
            Ok(results) => {
                if !results.is_empty() {
                    let rule_name = &results[0].identifier;
                    let live_filepath = if let Some(snapshot) = vss {
                        snapshot.remap_to_live(filepath)
                    } else {
                        filepath.to_path_buf()
                    };

                    let live_path_str = live_filepath.to_string_lossy().to_string();
                    let _ = quarantine_file(&live_filepath);
                    crate::alert::alert_user(&live_path_str, rule_name);
                    crate::alert::log_event(&live_path_str, rule_name);

                    if let Some(s) = stats {
                        s.threats_found.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Ok(mut th) = s.threats.lock() {
                            th.push((rule_name.to_string(), live_path_str));
                        }
                    }
                }
                break;
            },
            Err(e) => {
                let err_str = format!("{:?}", e);
                // Silence all un-scannable files (sockets, SYSTEM/TrustedInstaller DACLs, memory map blocks)
                if err_str.contains("code: 1920")
                    || err_str.contains("code: 5")
                    || err_str.contains("could not map file")
                    || err_str.contains("CouldNotMapFile")
                    || err_str.contains("Access is denied") {
                    break;
                }

                attempts += 1;
                if attempts < max_attempts {
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    if let Some(s) = stats {
        s.files_scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
