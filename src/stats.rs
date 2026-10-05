use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::thread;
use std::time::Duration;
use std::sync::Arc;
use std::io::{stdout, Write};

pub struct ScanStats {
    pub files_queued: AtomicUsize,
    pub files_scanned: AtomicUsize,
    pub threats_found: AtomicUsize,
    pub walk_finished: AtomicBool,
    pub current_file: Mutex<String>,
    pub threats: Mutex<Vec<(String, String)>>,
    pub start_time: Instant,
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            files_queued: AtomicUsize::new(0),
            files_scanned: AtomicUsize::new(0),
            threats_found: AtomicUsize::new(0),
            walk_finished: AtomicBool::new(false),
            current_file: Mutex::new(String::from("Initializing...")),
            threats: Mutex::new(Vec::new()),
            start_time: Instant::now(),
        }
    }
}

pub fn start_ui_loop(stats: Arc<ScanStats>, drive: &str, snapshot_name: &str, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    let drive_str = drive.to_string();
    let snapshot_str = snapshot_name.to_string();

    thread::spawn(move || {
        let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut spin_idx = 0;

        // Hide cursor
        print!("\x1B[?25l");
        let _ = stdout().flush();

        while running.load(Ordering::Relaxed) {
            render_hud(&stats, &drive_str, &snapshot_str, spinner[spin_idx % spinner.len()]);
            spin_idx += 1;
            thread::sleep(Duration::from_millis(80));
        }

        // Render final screen and restore cursor
        render_final_report(&stats, &drive_str);
        print!("\x1B[?25h");
        let _ = stdout().flush();
    })
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:<width$}", s, width = max_len)
    } else {
        let keep = max_len.saturating_sub(3);
        format!("...{}", &s[s.len() - keep..])
    }
}

fn render_hud(stats: &ScanStats, drive: &str, snapshot_name: &str, spin: &str) {
    let scanned = stats.files_scanned.load(Ordering::Relaxed);
    let queued = stats.files_queued.load(Ordering::Relaxed);
    let threats = stats.threats_found.load(Ordering::Relaxed);
    let elapsed = stats.start_time.elapsed().as_secs();
    let is_walk_done = stats.walk_finished.load(Ordering::Relaxed);

    let speed = if elapsed > 0 {
        scanned / (elapsed as usize)
    } else {
        scanned
    };

    let mins = elapsed / 60;
    let secs = elapsed % 60;

    let cur_file = stats.current_file.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let truncated_file = truncate_str(&cur_file, 50);

    // Progress percentage & bar
    let (percent, bar) = if is_walk_done && queued > 0 {
        let p = ((scanned as f64 / queued as f64) * 100.0).min(100.0);
        let filled = ((p / 100.0) * 28.0) as usize;
        let empty = 28usize.saturating_sub(filled);
        let b = format!("\x1B[36m{}\x1B[90m{}\x1B[0m", "█".repeat(filled), "░".repeat(empty));
        (format!("{:>5.1}%", p), b)
    } else {
        // Animated scanning scanner bar
        let pos = (scanned / 250) % 28;
        let mut b_chars = vec!['░'; 28];
        if pos < 28 {
            b_chars[pos] = '█';
            if pos > 0 { b_chars[pos - 1] = '▒'; }
            if pos + 1 < 28 { b_chars[pos + 1] = '▒'; }
        }
        let b_str: String = b_chars.into_iter().collect();
        let b = format!("\x1B[33m{}\x1B[0m", b_str);
        (String::from("CALC..."), b)
    };

    let threat_color = if threats > 0 { "\x1B[91m" } else { "\x1B[92m" };

    // Move cursor to top-left and render HUD
    print!("\x1B[H");
    println!("\x1B[96m╔══════════════════════════════════════════════════════════════════════════════╗\x1B[0m");
    println!("\x1B[96m║\x1B[0m                \x1B[1;97m⚡ SENTINEL // CYBER DEFENSE CORE ⚡\x1B[0m                          \x1B[96m║\x1B[0m");
    println!("\x1B[96m║\x1B[0m                     \x1B[93m[ FORENSIC VSS ENGINE v2.0 ]\x1B[0m                             \x1B[96m║\x1B[0m");
    println!("\x1B[96m╚══════════════════════════════════════════════════════════════════════════════╝\x1B[0m");
    println!(" \x1B[90mTarget:\x1B[0m \x1B[1m{}\x1B[0m | \x1B[90mSnapshot:\x1B[0m \x1B[33m{}\x1B[0m | \x1B[90mMode:\x1B[0m \x1B[32mZero-Lock Forensic Sweep\x1B[0m", drive, snapshot_name);
    println!("\x1B[90m────────────────────────────────────────────────────────────────────────────────\x1B[0m");

    println!(" \x1B[1;96m[SCANNING]\x1B[0m \x1B[93m{}\x1B[0m Examining: \x1B[97m{}\x1B[0m", spin, truncated_file);
    println!();
    println!("  Progress: [{}] \x1B[1;97m{}\x1B[0m", bar, percent);
    println!();
    println!("  \x1B[1;97m📊 Real-time Telemetry:\x1B[0m");
    println!("    ├─ Files Scanned : \x1B[1;97m{:<12}\x1B[0m ├─ Scan Speed : \x1B[1;96m{} files/sec\x1B[0m", format_num(scanned), format_num(speed));
    println!("    ├─ Files Queued  : \x1B[1;97m{:<12}\x1B[0m ├─ Elapsed    : \x1B[1;93m{:02}:{:02}\x1B[0m", format_num(queued), mins, secs);
    println!("    └─ Threats Found : {}{:<12}\x1B[0m └─ Status     : \x1B[32mActive (4 Cores)\x1B[0m", threat_color, threats);
    println!("\x1B[90m────────────────────────────────────────────────────────────────────────────────\x1B[0m");

    println!(" \x1B[1;91m🛑 THREAT DETECTION FEED:\x1B[0m");
    let threat_list = stats.threats.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if threat_list.is_empty() {
        println!("   \x1B[92m[✓] System Integrity Secure. No malicious signatures detected.\x1B[0m");
        println!("                                                                                ");
        println!("                                                                                ");
    } else {
        for (rule, path) in threat_list.iter().rev().take(3) {
            println!("   \x1B[91m[!] THREAT DETECTED:\x1B[0m \x1B[1m{}\x1B[0m -> \x1B[93m{}\x1B[0m [\x1B[91mQUARANTINED\x1B[0m]", rule, truncate_str(path, 40));
        }
        for _ in 0..(3usize.saturating_sub(threat_list.len())) {
            println!("                                                                                ");
        }
    }
    println!("\x1B[90m────────────────────────────────────────────────────────────────────────────────\x1B[0m");
    let _ = stdout().flush();
}

fn render_final_report(stats: &ScanStats, drive: &str) {
    let scanned = stats.files_scanned.load(Ordering::Relaxed);
    let threats = stats.threats_found.load(Ordering::Relaxed);
    let elapsed = stats.start_time.elapsed().as_secs();
    let mins = elapsed / 60;
    let secs = elapsed % 60;

    print!("\x1B[H\x1B[2J");
    println!("\x1B[92m╔══════════════════════════════════════════════════════════════════════════════╗\x1B[0m");
    println!("\x1B[92m║\x1B[0m                    \x1B[1;97m✨ FORENSIC VSS SCAN COMPLETE ✨\x1B[0m                          \x1B[92m║\x1B[0m");
    println!("\x1B[92m╚══════════════════════════════════════════════════════════════════════════════╝\x1B[0m");
    println!(" Target Scanned   : {}", drive);
    println!(" Files Evaluated  : \x1B[1;97m{}\x1B[0m", format_num(scanned));
    println!(" Time Elapsed     : \x1B[1;93m{:02}m {:02}s\x1B[0m", mins, secs);
    println!(" Threats Found    : {}{}\x1B[0m", if threats > 0 { "\x1B[1;91m" } else { "\x1B[1;92m" }, threats);
    println!("\x1B[90m────────────────────────────────────────────────────────────────────────────────\x1B[0m");

    let threat_list = stats.threats.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if threat_list.is_empty() {
        println!(" \x1B[1;92m[✓] STATUS: ALL CLEAR. No malware or malicious patterns detected.\x1B[0m");
    } else {
        println!(" \x1B[1;91m[!] ACTION REQUIRED: The following threats were neutralized & quarantined:\x1B[0m");
        for (rule, path) in threat_list {
            println!("   \x1B[91m•\x1B[0m \x1B[1m{}\x1B[0m: {} (\x1B[92mquarantine/*.quarantined\x1B[0m)", rule, path);
        }
    }
    println!("\x1B[90m────────────────────────────────────────────────────────────────────────────────\x1B[0m");
    println!(" \x1B[90mSnapshot detached and system memory reclaimed.\x1B[0m\n");
}

fn format_num(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    let chars: Vec<char> = s.chars().rev().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out.chars().rev().collect()
}
