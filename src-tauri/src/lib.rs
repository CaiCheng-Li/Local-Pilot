use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, State};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as AutostartManagerExt};
use tauri_plugin_notification::NotificationExt;
use workstation_audit::{AuditFilter, AuditRow, ShareFilter, ShareRow};
use workstation_core::config::Settings;
use workstation_core::paths::AppPaths;
use workstation_server::approvals::{ApprovalView, LocalDecision};
use workstation_server::auth::ClientRow;
use workstation_server::auth::oauth::PendingConnectionView;
use workstation_server::events::UiEvent;
use workstation_server::ui_api::{ProjectView, SetupRequest, StatusView};
use workstation_server::{Core, CoreOptions};

type AppResult<T> = Result<T, String>;

fn app_error(error: workstation_core::LpError) -> String {
    format!("{}: {}", error.code.as_str(), error.message)
}

#[tauri::command]
async fn local_mcp_services(
    core: State<'_, Arc<Core>>,
    action: String,
    id: Option<String>,
    config: Option<workstation_server::local_mcp::ServerConfig>,
) -> AppResult<Value> {
    core.ui_local_mcp(&action, id, config)
        .await
        .map_err(app_error)
}

#[tauri::command]
async fn status(core: State<'_, Arc<Core>>) -> AppResult<StatusView> {
    Ok(core.inner().ui_status().await)
}

#[tauri::command]
async fn complete_setup(
    app: tauri::AppHandle,
    core: State<'_, Arc<Core>>,
    request: SetupRequest,
) -> AppResult<StatusView> {
    let autostart = request.autostart;
    let status = core
        .inner()
        .ui_complete_setup(request)
        .await
        .map_err(app_error)?;
    sync_autostart(&app, autostart)?;
    Ok(status)
}

#[tauri::command]
fn clients(core: State<'_, Arc<Core>>) -> AppResult<Vec<ClientRow>> {
    core.ui_clients().map_err(app_error)
}

#[tauri::command]
fn create_client(core: State<'_, Arc<Core>>, name: String) -> AppResult<String> {
    core.ui_create_client(&name).map_err(app_error)
}

#[tauri::command]
fn create_manual_token(core: State<'_, Arc<Core>>, client_id: String) -> AppResult<Value> {
    core.ui_create_manual_token(
        &client_id,
        workstation_server::auth::ALL_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect(),
        Some("Desktop-created token".into()),
        None,
    )
    .map_err(app_error)
}

#[tauri::command]
fn set_client_enabled(
    core: State<'_, Arc<Core>>,
    client_id: String,
    enabled: bool,
) -> AppResult<()> {
    core.ui_set_client_enabled(&client_id, enabled)
        .map_err(app_error)
}

#[tauri::command]
fn disconnect_client(core: State<'_, Arc<Core>>, client_id: String) -> usize {
    core.ui_disconnect_client(&client_id)
}

#[tauri::command]
fn pending_connections(core: State<'_, Arc<Core>>) -> Vec<PendingConnectionView> {
    core.ui_pending_connections()
}

#[tauri::command]
fn decide_connection(
    core: State<'_, Arc<Core>>,
    request_id: String,
    approve: bool,
) -> AppResult<()> {
    core.ui_decide_connection(&request_id, approve, None, None)
        .map_err(app_error)
}

#[tauri::command]
fn approvals(core: State<'_, Arc<Core>>) -> Vec<ApprovalView> {
    core.ui_approvals(None, 250)
}

#[tauri::command]
fn decide_approval(
    core: State<'_, Arc<Core>>,
    approval_id: String,
    decision: LocalDecision,
) -> AppResult<ApprovalView> {
    core.ui_decide_approval(&approval_id, decision)
        .map_err(app_error)
}

#[tauri::command]
fn tasks(core: State<'_, Arc<Core>>) -> Vec<Value> {
    core.ui_tasks(false, 250)
        .into_iter()
        .filter_map(|task| serde_json::to_value(task).ok())
        .collect()
}

#[tauri::command]
fn task_output(core: State<'_, Arc<Core>>, task_id: String) -> AppResult<Value> {
    core.ui_task_output(&task_id, None, 256 * 1024)
        .and_then(|output| {
            serde_json::to_value(output).map_err(workstation_core::LpError::internal)
        })
        .map_err(app_error)
}

#[tauri::command]
fn stop_task(core: State<'_, Arc<Core>>, task_id: String, force: bool) -> AppResult<Value> {
    let task = if force {
        core.ui_kill_task(&task_id)
    } else {
        core.ui_cancel_task(&task_id)
    }
    .map_err(app_error)?;
    serde_json::to_value(task).map_err(|error| error.to_string())
}

#[tauri::command]
fn projects(core: State<'_, Arc<Core>>) -> Vec<ProjectView> {
    core.ui_projects()
}

#[tauri::command]
async fn refresh_projects(core: State<'_, Arc<Core>>) -> AppResult<usize> {
    core.ui_refresh_projects(None).await.map_err(app_error)
}

#[tauri::command]
async fn audit_events(core: State<'_, Arc<Core>>) -> AppResult<Vec<AuditRow>> {
    core.ui_audit_events(AuditFilter {
        limit: Some(250),
        ..Default::default()
    })
    .await
    .map_err(app_error)
}

#[tauri::command]
async fn shared_data(core: State<'_, Arc<Core>>) -> AppResult<Vec<ShareRow>> {
    core.ui_shares(ShareFilter {
        limit: Some(250),
        ..Default::default()
    })
    .await
    .map_err(app_error)
}

#[tauri::command]
fn settings(core: State<'_, Arc<Core>>) -> Settings {
    core.ui_settings()
}

#[tauri::command]
async fn save_settings(
    app: tauri::AppHandle,
    core: State<'_, Arc<Core>>,
    settings: Settings,
) -> AppResult<Settings> {
    let autostart = settings.general.autostart;
    let saved = core
        .inner()
        .update_settings(settings)
        .await
        .map(|settings| (*settings).clone())
        .map_err(app_error)?;
    sync_autostart(&app, autostart)?;
    Ok(saved)
}

#[tauri::command]
async fn set_remote_access(core: State<'_, Arc<Core>>, enabled: bool) -> AppResult<()> {
    if enabled {
        core.inner().enable_remote_access().await
    } else {
        core.inner().pause_remote_access().await
    }
    .map_err(app_error)
}

#[tauri::command]
async fn emergency_stop(core: State<'_, Arc<Core>>) -> AppResult<usize> {
    core.inner()
        .emergency_stop("local desktop")
        .await
        .map_err(app_error)
}

#[tauri::command]
async fn resume_after_emergency(core: State<'_, Arc<Core>>) -> AppResult<()> {
    core.inner().resume_remote_access().await.map_err(app_error)
}

#[tauri::command]
async fn restart_mcp(core: State<'_, Arc<Core>>) -> AppResult<()> {
    core.inner().restart_mcp(false).await.map_err(app_error)
}

#[tauri::command]
async fn stop_application(app: tauri::AppHandle, core: State<'_, Arc<Core>>) -> AppResult<()> {
    core.inner().shutdown().await;
    app.exit(0);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            let paths = AppPaths::resolve_default().map_err(app_error)?;
            let exe = std::env::current_exe()?;
            let install_dir = exe.parent().map(PathBuf::from);
            let helper_exe = install_dir
                .as_ref()
                .map(|directory| directory.join("local-pilot-elevated-helper.exe"));
            let core = tauri::async_runtime::block_on(Core::start(CoreOptions {
                paths,
                install_dir,
                settings_override: None,
                background: true,
                helper_exe,
            }))
            .map_err(app_error)?;
            sync_autostart(app.handle(), core.settings.get().general.autostart)?;
            app.manage(core.clone());

            let handle = app.handle().clone();
            let event_core = core.clone();
            let mut events = core.events.subscribe();
            tauri::async_runtime::spawn(async move {
                while let Ok(event) = events.recv().await {
                    if let Some((title, body)) = notification_for_event(&event_core, &event) {
                        let _ = handle
                            .notification()
                            .builder()
                            .title(title)
                            .body(body)
                            .show();
                    }
                    let _ = handle.emit("local-pilot", &event);
                }
            });

            let show = MenuItem::with_id(app, "show", "Show Local Pilot", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Stop Local Pilot", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("Local Pilot")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Some(core) = app.try_state::<Arc<Core>>() {
                                core.shutdown().await;
                            }
                            app.exit(0);
                        });
                    }
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }
            tray.build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let app = window.app_handle().clone();
                let close_to_tray = app
                    .try_state::<Arc<Core>>()
                    .map(|core| core.settings.get().general.close_to_tray)
                    .unwrap_or(true);
                if close_to_tray {
                    let _ = window.hide();
                } else {
                    tauri::async_runtime::spawn(async move {
                        if let Some(core) = app.try_state::<Arc<Core>>() {
                            core.shutdown().await;
                        }
                        app.exit(0);
                    });
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            local_mcp_services,
            status,
            complete_setup,
            clients,
            create_client,
            create_manual_token,
            set_client_enabled,
            disconnect_client,
            pending_connections,
            decide_connection,
            approvals,
            decide_approval,
            tasks,
            task_output,
            stop_task,
            projects,
            refresh_projects,
            audit_events,
            shared_data,
            settings,
            save_settings,
            set_remote_access,
            emergency_stop,
            resume_after_emergency,
            restart_mcp,
            stop_application
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Local Pilot");

    app.run(|app, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. })
            && let Some(core) = app.try_state::<Arc<Core>>()
            && core.state.get() != workstation_server::state::ServerState::Stopping
        {
            tauri::async_runtime::block_on(core.shutdown());
        }
    });
}

fn sync_autostart(app: &tauri::AppHandle, enabled: bool) -> AppResult<()> {
    if cfg!(debug_assertions) {
        return Ok(());
    }
    let manager = app.autolaunch();
    if enabled {
        manager.enable()
    } else {
        manager.disable()
    }
    .map_err(|error| format!("AUTOSTART_FAILED: {error}"))
}

fn notification_for_event(core: &Core, event: &UiEvent) -> Option<(&'static str, String)> {
    let settings = core.settings.get();
    if !settings.notifications.enabled {
        return None;
    }

    match event {
        UiEvent::ApprovalRequested {
            client,
            summary,
            requires_admin,
            ..
        } if settings.notifications.approvals => {
            let title = if *requires_admin {
                "Administrator approval required"
            } else {
                "Approval required"
            };
            Some((title, bounded_notification(&format!("{client}: {summary}"))))
        }
        UiEvent::ConnectionRequested {
            client_name,
            pairing_code,
            ..
        } if settings.notifications.connections => Some((
            "Connection approval required",
            format!("{client_name} is requesting access. Code: {pairing_code}"),
        )),
        UiEvent::ClientConnected { display_name, .. } if settings.notifications.connections => {
            Some(("Agent connected", bounded_notification(display_name)))
        }
        UiEvent::ClientDisconnected {
            display_name,
            reason,
            ..
        } if settings.notifications.connections => Some((
            "Agent disconnected",
            bounded_notification(&format!("{display_name}: {reason}")),
        )),
        UiEvent::TaskFailed { command, .. } if settings.notifications.task_failures => {
            Some(("Task failed", bounded_notification(command)))
        }
        UiEvent::AuditFault { message } => {
            Some(("Local Pilot audit fault", bounded_notification(message)))
        }
        UiEvent::EmergencyStop => Some((
            "Emergency stop activated",
            "Remote access is paused and running tasks were stopped.".into(),
        )),
        _ => None,
    }
}

fn bounded_notification(value: &str) -> String {
    const LIMIT: usize = 180;
    let mut output: String = value.chars().take(LIMIT).collect();
    if value.chars().count() > LIMIT {
        output.push('\u{2026}');
    }
    output
}
