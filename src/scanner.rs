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
