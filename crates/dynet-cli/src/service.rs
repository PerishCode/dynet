use std::{env, path::Path, time::Duration};

use dynet_capture::{
    CheckState, DnsMappingOptions, HookOptions, LinuxTakeover, RouterHookOptions, TrafficScope,
};
use dynet_cli::{DnsMappingAction, HooksAction, RouterHooksAction, ServiceAction};
use dynet_service::{HostRunner, ServiceController, ServiceSpec};
use dynet_state::AppState;

use crate::{
    paths::{resolve_config_relative, resolve_runtime_path},
    service_runtime,
};

pub(crate) fn run_hooks(action: HooksAction, config_path: Option<&Path>) -> Result<(), String> {
    let checks = match action {
        HooksAction::Status => {
            let options = configured_hook_options(config_path)?;
            LinuxTakeover::default().hooks_status_for_options(options)
        }
        HooksAction::Apply => {
            let options = configured_hook_options(config_path)?;
            for action in LinuxTakeover::default().hooks_apply_for(options)? {
                println!("{action}");
            }
            LinuxTakeover::default().hooks_status_for_options(options)
        }
        HooksAction::Cleanup => {
            for action in LinuxTakeover::default().hooks_cleanup()? {
                println!("{action}");
            }
            LinuxTakeover::default().hooks_status()
        }
    };
    crate::print_checks("hooks status", &checks);
    Ok(())
}

pub(crate) fn run_dns_mapping(
    action: DnsMappingAction,
    config_path: Option<&Path>,
) -> Result<(), String> {
    let takeover = LinuxTakeover::default();
    if action == DnsMappingAction::Cleanup {
        for action in takeover.dns_mapping_cleanup()? {
            println!("{action}");
        }
        return Ok(());
    }
    let options = configured_dns_mapping_options(config_path)?;
    match action {
        DnsMappingAction::Plan => {
            println!("dynet DNS mapping plan:");
            for item in takeover.dns_mapping_plan(&options)? {
                println!("- {item}");
            }
        }
        DnsMappingAction::Doctor => {
            let checks = takeover.dns_mapping_doctor_for(&options)?;
            crate::print_checks("dns-mapping doctor", &checks);
            if checks.iter().any(|check| check.state != CheckState::Ready) {
                return Err("dns mapping doctor requires the owned runtime skeleton".to_string());
            }
        }
        DnsMappingAction::Status => {
            let checks = takeover.dns_mapping_status_for(&options)?;
            crate::print_checks("dns-mapping status", &checks);
        }
        DnsMappingAction::Apply => {
            for action in takeover.dns_mapping_apply(&options)? {
                println!("{action}");
            }
            let checks = takeover.dns_mapping_status_for(&options)?;
            crate::print_checks("dns-mapping status", &checks);
            if checks.iter().any(|check| check.state != CheckState::Ready) {
                return Err("DNS mapping apply did not converge".to_string());
            }
        }
        DnsMappingAction::Cleanup => unreachable!("cleanup handled without configuration"),
    }
    Ok(())
}

pub(crate) fn run_router_hooks(
    action: RouterHooksAction,
    config_path: Option<&Path>,
) -> Result<(), String> {
    let takeover = LinuxTakeover::default();
    if action == RouterHooksAction::Cleanup {
        for action in takeover.router_hooks_cleanup()? {
            println!("{action}");
        }
        return Ok(());
    }
    let options = configured_router_hook_options(config_path)?;
    match action {
        RouterHooksAction::Plan => {
            println!("dynet router hook plan:");
            for item in takeover.router_hooks_plan(&options)? {
                println!("- {item}");
            }
        }
        RouterHooksAction::Doctor => {
            let checks = takeover.router_hooks_doctor_for(&options)?;
            crate::print_checks("router-hooks doctor", &checks);
            if checks.iter().any(|check| check.state != CheckState::Ready) {
                return Err(
                    "router hook doctor requires the owned runtime skeleton and selected interface"
                        .to_string(),
                );
            }
        }
        RouterHooksAction::Status => {
            let checks = takeover.router_hooks_status_for(&options)?;
            crate::print_checks("router-hooks status", &checks);
        }
        RouterHooksAction::Apply => {
            for action in takeover.router_hooks_apply(&options)? {
                println!("{action}");
            }
            let checks = takeover.router_hooks_status_for(&options)?;
            crate::print_checks("router-hooks status", &checks);
            if checks.iter().any(|check| check.state != CheckState::Ready) {
                return Err("router hook apply did not converge".to_string());
            }
        }
        RouterHooksAction::Cleanup => unreachable!("cleanup handled without configuration"),
    }
    Ok(())
}

fn configured_hook_options(config_path: Option<&Path>) -> Result<HookOptions, String> {
    let service_spec = spec(config_path)?;
    let identity = ServiceController::new(service_spec.clone()).identity()?;
    let state = AppState::from_config_path(Some(&service_spec.config))?;
    Ok(HookOptions {
        service_uid: identity.uid,
        ipv6_enabled: state.config.ipv6.enabled,
    })
}

fn configured_dns_mapping_options(config_path: Option<&Path>) -> Result<DnsMappingOptions, String> {
    let config_path =
        config_path.ok_or_else(|| "dns-mapping requires an explicit --config path".to_string())?;
    let state = AppState::from_config_path(Some(config_path))?;
    let scope = configured_traffic_scope(&state)?;
    if let Some(interface) = &state.config.dns_mapping.interface {
        if interface != &scope.interface {
            return Err(format!(
                "dns_mapping.interface {interface} must match capture.router_ingress.interface {}",
                scope.interface
            ));
        }
    }
    Ok(DnsMappingOptions {
        scope,
        source_port: state.config.dns_mapping.source_port,
        target: state.config.ingress.dns.bind,
        ipv6_enabled: state.config.ipv6.enabled,
    })
}

fn configured_router_hook_options(config_path: Option<&Path>) -> Result<RouterHookOptions, String> {
    let config_path =
        config_path.ok_or_else(|| "router-hooks requires an explicit --config path".to_string())?;
    let state = AppState::from_config_path(Some(config_path))?;
    Ok(RouterHookOptions {
        scope: configured_traffic_scope(&state)?,
        ipv6_enabled: state.config.ipv6.enabled,
    })
}

fn configured_traffic_scope(state: &AppState) -> Result<TrafficScope, String> {
    let config = &state.config.capture.router_ingress;
    let interface = config.interface.clone().ok_or_else(|| {
        "traffic integration requires capture.router_ingress.interface in the configuration"
            .to_string()
    })?;
    Ok(TrafficScope {
        interface,
        ipv4_sources: config.ipv4_sources.clone(),
        ipv6_sources: config.ipv6_sources.clone(),
    })
}

pub(crate) async fn run(action: ServiceAction, config_path: Option<&Path>) -> Result<(), String> {
    if action == ServiceAction::Reload {
        return reload(config_path).await;
    }
    let spec = spec(config_path)?;
    let control_bind = AppState::from_config_path(Some(&spec.config))?
        .config
        .control
        .bind;
    if action == ServiceAction::Supervise {
        return dynet_service::supervise(&spec, || {
            let takeover = LinuxTakeover::default();
            takeover.router_hooks_cleanup()?;
            takeover.hooks_cleanup()?;
            takeover.dns_mapping_cleanup()?;
            Ok(())
        })
        .await;
    }
    let controller = ServiceController::new(spec);
    match action {
        ServiceAction::Plan => {
            let plan = controller.plan()?;
            println!("dynet service plan manager={}:", plan.manager.label());
            for item in plan.items {
                println!("- {item}");
            }
        }
        ServiceAction::Doctor => {
            let checks = controller.doctor()?;
            print_control_checks("doctor", &checks);
            require_ready("doctor", &checks)?;
        }
        ServiceAction::Status => status(&controller, control_bind).await?,
        ServiceAction::Apply => {
            let report = controller.apply()?;
            for change in report.changed {
                println!("{change}");
            }
            println!("restart-required: {}", report.restart_required);
            let runtime = service_runtime::wait_ready(control_bind, Duration::from_secs(8)).await?;
            require_capture_ready()?;
            println!("runtime-generation: {}", runtime.generation);
        }
        ServiceAction::Cleanup => {
            let report = controller.cleanup()?;
            for change in report.changed {
                println!("{change}");
            }
        }
        ServiceAction::Start => {
            controller.start()?;
            service_runtime::wait_ready(control_bind, Duration::from_secs(8)).await?;
            require_capture_ready()?;
        }
        ServiceAction::Stop { cleanup_hooks } => {
            prepare_stop(cleanup_hooks)?;
            controller.stop()?;
        }
        ServiceAction::Restart { cleanup_hooks } => {
            prepare_stop(cleanup_hooks)?;
            controller.restart()?;
            service_runtime::wait_ready(control_bind, Duration::from_secs(8)).await?;
            require_capture_ready()?;
        }
        ServiceAction::Reload => unreachable!("reload handled before config validation"),
        ServiceAction::Logs { lines, follow } => controller.logs(lines, follow)?,
        ServiceAction::Supervise => unreachable!("supervise handled before controller"),
    }
    Ok(())
}

async fn status(
    controller: &ServiceController<HostRunner>,
    control_bind: std::net::SocketAddr,
) -> Result<(), String> {
    let status = controller.status()?;
    print_control_checks("status", &status.checks);
    println!("manager: {}", status.manager.label());
    println!("enabled: {}", status.enabled);
    println!("active: {}", status.active);
    println!(
        "main-pid: {}",
        status
            .main_pid
            .map_or_else(|| "unavailable".to_string(), |pid| pid.to_string())
    );
    require_ready("status", &status.checks)?;
    let capture = LinuxTakeover::default().status();
    crate::print_takeover_status("service", &capture);
    if status.active
        && capture
            .runtime
            .iter()
            .any(|check| check.state != CheckState::Ready)
    {
        return Err("active dynet service has an incomplete capture runtime skeleton".to_string());
    }
    match service_runtime::status(control_bind).await {
        Ok(runtime) => {
            println!("runtime-generation: {}", runtime.generation);
            println!("runtime-fingerprint: {}", runtime.fingerprint);
            println!(
                "runtime-last-reload: {}",
                runtime.last_reload_outcome.as_deref().unwrap_or("none")
            );
            Ok(())
        }
        Err(error) if status.active => Err(format!("active dynet service is unhealthy: {error}")),
        Err(_) => {
            println!("runtime: unavailable");
            Ok(())
        }
    }
}

fn require_capture_ready() -> Result<(), String> {
    let status = LinuxTakeover::default().status();
    if status
        .runtime
        .iter()
        .all(|check| check.state == CheckState::Ready)
    {
        Ok(())
    } else {
        Err("dynet service started without a ready capture runtime skeleton".to_string())
    }
}

async fn reload(config_path: Option<&Path>) -> Result<(), String> {
    let config_path = config_path
        .ok_or_else(|| "dynet service reload requires an explicit --config path".to_string())?;
    let config_path = config_path
        .canonicalize()
        .map_err(|error| format!("failed resolving config {}: {error}", config_path.display()))?;
    let executable = env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("failed resolving dynet executable: {error}"))?;
    let (spec, control_bind) = match AppState::from_config_path(Some(&config_path)) {
        Ok(state) => {
            let runtime_database =
                resolve_runtime_path(&state.config.service.runtime_database, Some(&config_path))?;
            let environment_file = state
                .config
                .service
                .environment_file
                .as_deref()
                .map(|path| resolve_config_relative(path, Some(&config_path)))
                .transpose()?;
            (
                ServiceSpec {
                    manager: state.config.service.manager,
                    user: state.config.service.user,
                    executable,
                    config: config_path,
                    runtime_database,
                    environment_file,
                },
                state.config.control.bind,
            )
        }
        Err(error) => {
            eprintln!(
                "dynet: service reload candidate is invalid before signaling; using installed manager recovery path: {error}"
            );
            let bind = env::var("DYNET_CONTROL_BIND")
                .unwrap_or_else(|_| "127.0.0.1:9977".to_string())
                .parse()
                .map_err(|error| format!("DYNET_CONTROL_BIND is invalid: {error}"))?;
            (
                ServiceSpec {
                    manager: dynet_state::ServiceManager::Auto,
                    user: "unresolved".to_string(),
                    executable,
                    config: config_path.clone(),
                    runtime_database: config_path.with_extension("sqlite"),
                    environment_file: None,
                },
                bind,
            )
        }
    };
    let after_id = service_runtime::latest_reload(control_bind)
        .await?
        .map_or(0, |audit| audit.id);
    ServiceController::new(spec).reload()?;
    let audit =
        service_runtime::wait_reload_after(control_bind, after_id, Duration::from_secs(3)).await?;
    println!("reload-outcome: {}", audit.outcome);
    println!("runtime-generation: {}", audit.generation_after);
    if !audit.changed_fields.is_empty() {
        println!("changed-fields: {}", audit.changed_fields.join(","));
    }
    if !audit.restart_required_fields.is_empty() {
        println!(
            "restart-required-fields: {}",
            audit.restart_required_fields.join(",")
        );
    }
    if matches!(audit.outcome.as_str(), "applied" | "no-op") {
        Ok(())
    } else {
        Err(format!("dynet service reload outcome={}", audit.outcome))
    }
}

fn spec(config_path: Option<&Path>) -> Result<ServiceSpec, String> {
    let config_path = config_path.ok_or_else(|| {
        "dynet service and hooks apply require an explicit --config path".to_string()
    })?;
    let config_path = config_path
        .canonicalize()
        .map_err(|error| format!("failed resolving config {}: {error}", config_path.display()))?;
    let state = AppState::from_config_path(Some(&config_path))?;
    let executable = env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("failed resolving dynet executable: {error}"))?;
    let runtime_database =
        resolve_runtime_path(&state.config.service.runtime_database, Some(&config_path))?;
    let environment_file = state
        .config
        .service
        .environment_file
        .as_deref()
        .map(|path| resolve_config_relative(path, Some(&config_path)))
        .transpose()?;
    Ok(ServiceSpec {
        manager: state.config.service.manager,
        user: state.config.service.user,
        executable,
        config: config_path,
        runtime_database,
        environment_file,
    })
}

fn prepare_stop(cleanup_hooks: bool) -> Result<(), String> {
    let takeover = LinuxTakeover::default();
    let hooks = takeover.hooks_status();
    if !hooks.iter().any(|check| check.state == CheckState::Ready) {
        return Ok(());
    }
    if !cleanup_hooks {
        return Err(
            "dynet hooks are active; service stop/restart requires --cleanup-hooks".to_string(),
        );
    }
    for action in takeover.router_hooks_cleanup()? {
        println!("{action}");
    }
    for action in takeover.hooks_cleanup()? {
        println!("{action}");
    }
    Ok(())
}

fn print_control_checks(label: &str, checks: &[dynet_service::ServiceCheck]) {
    println!("dynet service {label}:");
    for check in checks {
        println!("- {}: {} {}", check.id, check.state.label(), check.detail);
    }
}

fn require_ready(label: &str, checks: &[dynet_service::ServiceCheck]) -> Result<(), String> {
    let failures = checks
        .iter()
        .filter(|check| check.state != dynet_service::ResourceState::Ready)
        .map(|check| format!("{}={}", check.id, check.state.label()))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "dynet service {label} failed: {}",
            failures.join(", ")
        ))
    }
}
