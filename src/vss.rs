use std::process::Command;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

pub struct VssSnapshot {
    pub id: String,
    pub mount_path: String,
    pub drive_letter: String,
}

impl Drop for VssSnapshot {
    fn drop(&mut self) {
        println!("Cleaning up VSS Snapshot: {}", self.id);
        let _ = Command::new("vssadmin")
            .args(&["delete", "shadows", &format!("/Shadow={}", self.id), "/Quiet"])
            .output();
    }
}

impl VssSnapshot {
    pub fn remap_to_live(&self, vss_path: &Path) -> PathBuf {
        let vss_str = vss_path.to_string_lossy().to_string();
        if vss_str.starts_with(&self.mount_path) {
            let relative = &vss_str[self.mount_path.len()..];
            // E.g., strips `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\`
            // relative becomes `Users\siddh\malware.exe` or `\Users\siddh...`
            let trimmed = relative.trim_start_matches('\\');
            let drive_prefix = self.drive_letter.trim_end_matches('\\'); // e.g. "C:"
            let mut live_path = PathBuf::from(drive_prefix);
            live_path.push("\\");
            live_path.push(trimmed);
            live_path
        } else {
            vss_path.to_path_buf()
        }
    }

    pub fn create(drive: &str) -> std::io::Result<Self> {
        let wmic_out = Command::new("wmic")
            .args(&["shadowcopy", "call", "create", &format!("Volume=\"{}\"", drive)])
            .output()?;

        let output_str = String::from_utf8_lossy(&wmic_out.stdout);
        let mut shadow_id = String::new();
        // Super basic parse, assuming output matches standard wmic format where ShadowID exists
        for line in output_str.lines() {
            if line.contains("ShadowID = ") {
                if let Some(id_part) = line.split('"').nth(1) {
                    shadow_id = id_part.to_string();
                }
            }
        }

        if shadow_id.is_empty() {
            return Err(Error::new(ErrorKind::Other, "Failed to extract ShadowID from wmic"));
        }

        let list_out = Command::new("vssadmin")
            .args(&["list", "shadows"])
            .output()?;

        let list_str = String::from_utf8_lossy(&list_out.stdout);
        let mut mount_path = String::new();
        let mut found_id = false;

        for line in list_str.lines() {
            if line.contains(&shadow_id) {
                found_id = true;
            }
            if found_id && line.contains("Shadow Copy Volume Name:") {
                let parts: Vec<&str> = line.split("Shadow Copy Volume Name:").collect();
                if parts.len() > 1 {
                    mount_path = parts[1].trim().to_string();
                    break;
                }
            }
        }

        if mount_path.is_empty() {
            // Ensure we attempt cleanup gracefully if path resolution fails
            let _ = Command::new("vssadmin")
                .args(&["delete", "shadows", &format!("/Shadow={}", shadow_id), "/Quiet"])
                .output();
            return Err(Error::new(ErrorKind::NotFound, "Failed to find Mount Path in vssadmin"));
        }

        Ok(VssSnapshot {
            id: shadow_id,
            mount_path,
            drive_letter: drive.to_string(),
        })
    }
}
