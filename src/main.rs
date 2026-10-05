mod rules;
mod quarantine;
mod scanner;
mod alert;

use std::fs;

fn setup_directories() -> std::io::Result<()> {
    fs::create_dir_all("rules")?;
    fs::create_dir_all("quarantine")?;
    Ok(())
}

fn main() {
    setup_directories().expect("Failed to create base directories");
    println!("Scanner starting...");
}
