use yara::{Compiler, Error};
use std::fs;
use std::path::Path;

pub fn compile_rules<P: AsRef<Path>>(dir: P) -> Result<Compiler, Error> {
    let mut compiler = Compiler::new()?;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                compiler = compiler.add_rules_file(path)?;
            }
        }
    }
    Ok(compiler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_compile_rules() {
        std::fs::create_dir_all("test_rules").unwrap();
        let mut file = File::create("test_rules/dummy.yar").unwrap();
        file.write_all(b"rule dummy { condition: true }").unwrap();

        let compiler = compile_rules("test_rules");
        assert!(compiler.is_ok());
        std::fs::remove_dir_all("test_rules").unwrap();
    }
}
