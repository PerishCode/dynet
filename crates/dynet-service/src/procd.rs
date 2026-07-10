use std::path::PathBuf;

use crate::{artifact::managed_content, ServicePaths, ServiceSpec};

pub(crate) fn init_path(paths: &ServicePaths) -> PathBuf {
    paths.procd_init_dir.join("dynet")
}

pub(crate) fn init_content(spec: &ServiceSpec) -> Result<String, String> {
    let executable = shell_arg(&spec.executable)?;
    let config = shell_arg(&spec.config)?;
    let environment = match spec.environment_file.as_ref() {
        Some(path) => format!(
            "\n    while IFS= read -r entry; do\n        case \"$entry\" in ''|'#'*) continue ;; esac\n        procd_append_param env \"$entry\"\n    done < {}",
            shell_arg(path)?
        ),
        None => String::new(),
    };
    let payload = format!(
        "#!/bin/sh /etc/rc.common\n\n\
USE_PROCD=1\n\
START=95\n\
STOP=10\n\n\
start_service() {{\n\
    procd_open_instance\n\
    procd_set_param command {executable} service supervise --config {config}\n\
    procd_set_param respawn 3600 5 5\n\
    procd_set_param stdout 1\n\
    procd_set_param stderr 1\n\
    procd_set_param limits nofile='4096 4096'{environment}\n\
    procd_close_instance\n\
}}\n\n\
reload_service() {{\n\
    procd_send_signal dynet '*' HUP\n\
}}\n\n\
stop_service() {{\n\
    {executable} hooks cleanup --config {config}\n\
}}\n"
    );
    Ok(managed_content(&payload))
}

fn shell_arg(path: &std::path::Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("service path {} is not UTF-8", path.display()))?;
    if !path.is_absolute() {
        return Err(format!("service path {} must be absolute", path.display()));
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
