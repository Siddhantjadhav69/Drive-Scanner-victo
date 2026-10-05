use yara::Rules;
use std::path::Path;
use crate::quarantine::quarantine_file;
use std::thread;
use std::time::Duration;

pub fn scan_path(rules: &Rules, filepath: &Path) {
    if !filepath.is_file() {
        return; // Ignore directories or non-existent files
    }

    let mut attempts = 0;
    let max_attempts = 5;

    // Retry loop for locked files (Code 32 / PermissionDenied)
    while attempts < max_attempts {
        match rules.scan_file(filepath, 10) {
            Ok(results) => {
                if !results.is_empty() {
                    let rule_name = &results[0].identifier;
                    if let Err(e) = quarantine_file(filepath) {
                        println!("Warning: Quarantine failed for {}: {:?}", filepath.display(), e);
                    } else {
                        crate::alert::alert_user(&filepath.display().to_string(), rule_name);
                        crate::alert::log_event(&filepath.display().to_string(), rule_name);
                    }
                }
                return; // Success, exit the loop
            },
            Err(e) => {
                attempts += 1;
                if attempts == max_attempts {
                    println!("Gave up scanning {} after {} attempts: {:?}", filepath.display(), max_attempts, e);
                } else {
                    // Wait 50 milliseconds and try again
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}
