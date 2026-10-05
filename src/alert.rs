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
