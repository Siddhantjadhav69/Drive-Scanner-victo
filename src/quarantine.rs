use std::path::Path;
use std::fs;
use std::io;

pub fn quarantine_file(filepath: &Path) -> io::Result<()> {
    if let Some(filename) = filepath.file_name() {
        let mut new_filename = filename.to_os_string();
        new_filename.push(".quarantined");
        let dest = Path::new("quarantine").join(new_filename);
        fs::rename(filepath, dest)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;

    #[test]
    fn test_quarantine_action() {
        std::fs::create_dir_all("quarantine").unwrap();
        let test_file = PathBuf::from("test_malware.txt");
        File::create(&test_file).unwrap();

        quarantine_file(&test_file).unwrap();

        assert!(!test_file.exists());
        let quarantined_path = PathBuf::from("quarantine/test_malware.txt.quarantined");
        assert!(quarantined_path.exists());

        std::fs::remove_file(quarantined_path).unwrap();
    }
}
