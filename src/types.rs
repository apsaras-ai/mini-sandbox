use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Component, Path};

pub const MAX_CODE_BYTES: usize = 128 * 1024;
pub const MAX_FILE_BYTES: usize = 512 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 128 * 1024;
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

fn default_timeout() -> u64 {
    5_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub code: String,
    pub language: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub files: Vec<FileInput>,
    #[serde(default)]
    pub env_vars: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInput {
    pub path: String,
    #[serde(with = "base64_bytes")]
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub peak_memory_bytes: u64,
    #[serde(default)]
    pub output_truncated: bool,
    #[serde(default)]
    pub oom_killed: bool,
}

impl ExecuteResponse {
    pub fn timeout(duration_ms: u64) -> Self {
        Self {
            stdout: String::new(),
            stderr: "sandbox execution deadline exceeded".to_owned(),
            exit_code: -1,
            duration_ms,
            timed_out: true,
            peak_memory_bytes: 0,
            output_truncated: false,
            oom_killed: false,
        }
    }
}

impl ExecuteRequest {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.language.as_str(), "python" | "node" | "nodejs") {
            bail!("language must be python, node or nodejs");
        }
        if self.code.is_empty() || self.code.len() > MAX_CODE_BYTES {
            bail!("code must contain 1..={MAX_CODE_BYTES} bytes");
        }
        if !(1..=30_000).contains(&self.timeout_ms) {
            bail!("timeout_ms must be between 1 and 30000");
        }
        if self.files.len() > 64 {
            bail!("too many input files");
        }
        let mut total = 0usize;
        let mut paths = HashSet::new();
        for file in &self.files {
            let path = Path::new(&file.path);
            if file.path.is_empty()
                || file.path.len() > 256
                || !path.components().all(|c| matches!(c, Component::Normal(_)))
                || file.path.contains('\\')
                || file.path.contains('\0')
            {
                bail!("file paths must be relative with no '.' or '..' components");
            }
            if file.path == "__mini_sandbox_main__.py"
                || file.path == "__mini_sandbox_main__.js"
            {
                bail!("reserved input file path");
            }
            if !paths.insert(file.path.as_str()) {
                bail!("duplicate input file path");
            }
            total = total.checked_add(file.content.len()).ok_or_else(|| anyhow::anyhow!("input size overflow"))?;
            if total > MAX_FILE_BYTES {
                bail!("input files exceed {MAX_FILE_BYTES} bytes");
            }
        }
        for path in &paths {
            let mut ancestor = Path::new(path).parent();
            while let Some(dir) = ancestor {
                if paths.contains(dir.to_str().unwrap_or_default()) {
                    bail!("input file is also a parent directory");
                }
                ancestor = dir.parent().filter(|p| !p.as_os_str().is_empty());
            }
        }
        if self.env_vars.len() > 32 {
            bail!("too many environment variables");
        }
        let mut keys = HashSet::new();
        for (key, value) in &self.env_vars {
            let valid = !key.is_empty()
                && key.len() <= 64
                && (key.as_bytes()[0].is_ascii_alphabetic() || key.starts_with('_'))
                && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
            if !valid || value.len() > 4096 || value.contains('\0') || !keys.insert(key) {
                bail!("invalid or duplicate environment variable");
            }
            let upper = key.to_ascii_uppercase();
            if upper == "PATH"
                || upper == "HOME"
                || upper == "TMPDIR"
                || upper == "ENV"
                || upper == "BASH_ENV"
                || upper.starts_with("LD_")
                || upper.starts_with("PYTHON")
                || upper.starts_with("NODE_")
            {
                bail!("environment variable {key} is reserved");
            }
        }
        Ok(())
    }
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_and_default_timeout() {
        let req: ExecuteRequest = serde_json::from_str(r#"{"code":"print(1)","language":"python","files":[{"path":"hello.txt","content":"aGk="}]}"#).unwrap();
        assert_eq!(req.timeout_ms, 5000);
        assert_eq!(req.files[0].content, b"hi");
        req.validate().unwrap();
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("aGk="));
    }

    #[test]
    fn response_serialization() {
        let response = ExecuteResponse::timeout(3000);
        assert_eq!(serde_json::to_value(&response).unwrap()["timed_out"], true);
    }

    #[test]
    fn rejects_traversal_and_reserved_env() {
        let mut req = ExecuteRequest {
            code: "print(1)".into(),
            language: "python".into(),
            timeout_ms: 5000,
            files: vec![FileInput { path: "../outside".into(), content: vec![] }],
            env_vars: vec![],
        };
        assert!(req.validate().is_err());
        req.files[0].path = "dir/file".into();
        req.env_vars.push(("LD_PRELOAD".into(), "x".into()));
        assert!(req.validate().is_err());
    }
}
