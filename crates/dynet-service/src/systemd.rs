use std::path::PathBuf;

use crate::{artifact::managed_content, ServicePaths, ServiceSpec};

pub(crate) fn unit_path(paths: &ServicePaths) -> PathBuf {
    paths.systemd_system_dir.join("dynet.service")
}

pub(crate) fn unit_content(spec: &ServiceSpec) -> Result<String, String> {
    let executable = path_arg(&spec.executable)?;
    let config = path_arg(&spec.config)?;
    let environment = match &spec.environment_file {
        Some(path) => format!("EnvironmentFile={}\n", path_arg(path)?),
        None => String::new(),
    };
    let payload = format!(
        "[Unit]\n\
Description=dynet full-takeover runtime\n\
After=network-online.target\n\
Wants=network-online.target\n\n\
[Service]\n\
Type=simple\n\
User={user}\n\
{environment}\
ExecStartPre=+{executable} hooks cleanup --config {config}\n\
ExecStartPre=+{executable} dns-mapping cleanup --config {config}\n\
ExecStartPre=+{executable} apply --auto\n\
ExecStart={executable} run --config {config}\n\
ExecReload=/bin/kill -HUP $MAINPID\n\
ExecStopPost=+{executable} hooks cleanup --config {config}\n\
ExecStopPost=+{executable} dns-mapping cleanup --config {config}\n\
Restart=on-failure\n\
RestartSec=1s\n\
KillSignal=SIGTERM\n\
TimeoutStopSec=10s\n\
LimitNOFILE=4096\n\
AmbientCapabilities=CAP_NET_ADMIN\n\
CapabilityBoundingSet=CAP_NET_ADMIN\n\
NoNewPrivileges=true\n\n\
[Install]\n\
WantedBy=multi-user.target\n",
        user = spec.user,
    );
    Ok(managed_content(&payload))
}

fn path_arg(path: &std::path::Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("service path {} is not UTF-8", path.display()))?;
    if !path.is_absolute() {
        return Err(format!("service path {} must be absolute", path.display()));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!(
            "service path {} must not contain whitespace",
            path.display()
        ));
    }
    Ok(value.to_string())
}
