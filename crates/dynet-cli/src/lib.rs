use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub process_stamp: Option<String>,
}

impl Args {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut parsed = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            if arg == "--config" {
                let Some(path) = args.next() else {
                    return Err("--config requires a path".to_string());
                };
                set_config(&mut parsed, PathBuf::from(path))?;
            } else if arg == "--process-stamp" {
                let Some(stamp) = args.next() else {
                    return Err("--process-stamp requires a value".to_string());
                };
                set_process_stamp(&mut parsed, stamp.to_string_lossy().to_string())?;
            } else if let Some(path) = split_config_arg(&arg) {
                set_config(&mut parsed, path)?;
            } else if let Some(stamp) = split_process_stamp_arg(&arg) {
                set_process_stamp(&mut parsed, stamp)?;
            } else {
                return Err(format!("unknown argument {}", arg.to_string_lossy()));
            }
        }
        Ok(parsed)
    }
}

fn split_config_arg(arg: &OsString) -> Option<PathBuf> {
    let value = arg.to_str()?;
    value
        .strip_prefix("--config=")
        .map(|path| Path::new(path).to_path_buf())
}

fn split_process_stamp_arg(arg: &OsString) -> Option<String> {
    let value = arg.to_str()?;
    value
        .strip_prefix("--process-stamp=")
        .map(|stamp| stamp.to_string())
}

fn set_config(args: &mut Args, path: PathBuf) -> Result<(), String> {
    if args.config.is_some() {
        return Err("--config can only be provided once".to_string());
    }
    if path.as_os_str().is_empty() {
        return Err("--config requires a non-empty path".to_string());
    }
    args.config = Some(path);
    Ok(())
}

fn set_process_stamp(args: &mut Args, stamp: String) -> Result<(), String> {
    if args.process_stamp.is_some() {
        return Err("--process-stamp can only be provided once".to_string());
    }
    if stamp.is_empty() {
        return Err("--process-stamp requires a non-empty value".to_string());
    }
    args.process_stamp = Some(stamp);
    Ok(())
}
