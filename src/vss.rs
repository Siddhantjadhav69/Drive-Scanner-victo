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
        let ps_out = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                &format!("(Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume='{}'}}).ShadowID", drive),
            ])
            .output()?;

        let output_str = String::from_utf8_lossy(&ps_out.stdout);
        let shadow_id = output_str.trim().to_string();

        if shadow_id.is_empty() || !shadow_id.starts_with('{') {
            return Err(Error::new(ErrorKind::Other, format!("Failed to create VSS or extract ShadowID from PowerShell. Output: {}", output_str)));
        }

        let ps_path_out = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                &format!("(Get-CimInstance Win32_ShadowCopy | Where-Object DeviceID -eq '{}').DeviceObject", shadow_id),
            ])
            .output()?;

        let path_str = String::from_utf8_lossy(&ps_path_out.stdout);
        let mount_path = path_str.trim().to_string();

        if mount_path.is_empty() {
            // Ensure we attempt cleanup gracefully if path resolution fails
            let _ = Command::new("vssadmin")
                .args(&["delete", "shadows", &format!("/Shadow={}", shadow_id), "/Quiet"])
                .output();
            return Err(Error::new(ErrorKind::NotFound, "Failed to find Mount Path using PowerShell"));
        }

        Ok(VssSnapshot {
            id: shadow_id,
            mount_path,
            drive_letter: drive.to_string(),
        })
    }
}
