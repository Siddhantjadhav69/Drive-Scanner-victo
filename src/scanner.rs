use yara::Rules;
use std::path::Path;
use crate::quarantine::quarantine_file;

pub fn scan_path(rules: &Rules, filepath: &Path) {
    if !filepath.is_file() {
        return; // Ignore directories or non-existent files
    }

    // Attempt to scan. Catch permission errors gracefully.
    match rules.scan_file(filepath, 10) {
        Ok(results) => {
            if !results.is_empty() {
                let rule_name = &results[0].identifier;
                if let Err(e) = quarantine_file(filepath) {
                    println!("Warning: Quarantine failed: {:?}", e);
                } else {
                    crate::alert::alert_user(&filepath.display().to_string(), rule_name);
                    crate::alert::log_event(&filepath.display().to_string(), rule_name);
                }
            }
        },
        Err(e) => {
            println!("Warning: Could not scan {}: {:?}", filepath.display(), e);
        }
    }
}
