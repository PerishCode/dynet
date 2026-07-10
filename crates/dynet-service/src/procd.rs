use std::path::PathBuf;

use crate::{artifact::managed_content, ServicePaths, ServiceRunner, ServiceSpec, SERVICE_NAME};

pub(crate) fn main_pid(runner: &impl ServiceRunner) -> Option<u32> {
    let output = runner
        .run(
            "ubus",
            &["call", "service", "list", r#"{"name":"dynet"}"#]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
        .ok()?;
    if !output.success {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(&output.stdout).ok()?;
    value
        .get(SERVICE_NAME)?
        .get("instances")?
        .as_object()?
        .values()
        .find(|instance| instance.get("running").and_then(|value| value.as_bool()) == Some(true))?
        .get("pid")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
}

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
    {executable} router-hooks cleanup --config {config}\n\
    {executable} hooks cleanup --config {config}\n\
    {executable} dns-mapping cleanup --config {config}\n\
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
