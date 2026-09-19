//! Adversarial tests (plan sections 9, 45 and 60): traversal, junction,
//! symlink and hard-link escapes, namespace tricks, concurrent reparse-point
//! swaps and cross-client access. These exercise the structured-tool broker
//! (strict enforcement), not raw shell containment.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use local_pilot_tests::*;
use serde_json::json;
use workstation_server::approvals::LocalDecision;

#[tokio::test]
async fn traversal_resolves_to_real_destination() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("project")).unwrap();
    std::fs::write(
        h.dir.path().join("Documents").join("secret.txt"),
        "outside-the-root",
    )
    .unwrap();
    // Reads outside are allowed (not protected) but are classified as external.
    let r = h
        .ok(
            "fs_read_text",
            json!({ "path": r"project\..\..\secret.txt" }),
        )
        .await;
    assert!(
        r["path"]
            .as_str()
            .unwrap()
            .ends_with(r"Documents\secret.txt")
    );
    // Writes via traversal need approval; nothing lands outside.
    h.needs_approval(
        "fs_write_text",
        json!({ "path": r"project\..\..\escape.txt", "content": "x" }),
    )
    .await;
    assert!(!h.dir.path().join("Documents").join("escape.txt").exists());
    h.needs_approval(
        "fs_write_text",
        json!({ "path": "project/../../../escape2.txt", "content": "x" }),
    )
    .await;
}

#[tokio::test]
async fn sibling_directories_are_not_trusted() {
    let h = Harness::new().await;
    for sib in ["Projects2", "Projects-Backup"] {
        let d = h.dir.path().join("Documents").join(sib);
        std::fs::create_dir_all(&d).unwrap();
        h.needs_approval(
            "fs_write_text",
            json!({ "path": d.join("x.txt").display().to_string(), "content": "x" }),
        )
        .await;
        assert!(!d.join("x.txt").exists());
    }
}

#[tokio::test]
async fn namespace_tricks_are_rejected() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("p")).unwrap();
    std::fs::write(h.projects.join("p").join("f.txt"), "data").unwrap();
    let drive = &h.projects.display().to_string()[..2];
    for p in [
        r"\\localhost\C$\Windows\win.ini".to_string(),
        r"\\server\share\x.txt".to_string(),
        r"\\?\UNC\localhost\C$\x".to_string(),
        r"\\.\C:\Windows\win.ini".to_string(),
        r"\\.\PhysicalDrive0".to_string(),
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\x".to_string(),
        format!("{}:stream", h.path("p/f.txt")),
        format!("{}::$DATA", h.path("p/f.txt")),
        format!("{drive}relative.txt"),
        h.path("p/con"),
        h.path("p/NUL.txt"),
    ] {
        let (err, v) = h.call("fs_read_text", json!({ "path": p })).await;
        assert!(err, "{p} should be rejected: {v}");
        let code = v["error"]["code"].as_str().unwrap();
        assert!(
            code == "PATH_OUTSIDE_POLICY" || code == "INVALID_ARGUMENTS",
            "{p}: {code}"
        );
        let (err, _) = h
            .call("fs_write_text", json!({ "path": p, "content": "x" }))
            .await;
        assert!(err, "{p} write should be rejected");
    }
    // \\?\ drive paths are aliases: classified by their destination.
    let verbatim = format!(r"\\?\{}", h.path("p/f.txt"));
    let r = h.ok("fs_read_text", json!({ "path": verbatim })).await;
    assert_eq!(r["content"], "data");
    let verbatim_out = format!(r"\\?\{}", h.outside.join("v.txt").display());
    h.needs_approval(
        "fs_write_text",
        json!({ "path": verbatim_out, "content": "x" }),
    )
    .await;
    // Trailing dots/spaces do not hide protected names.
    std::fs::write(h.projects.join("p").join(".env"), "S=1").unwrap();
    let (err, v) = h
        .call(
            "fs_read_text",
            json!({ "path": format!("{}. ", h.path("p/.env")) }),
        )
        .await;
    assert!(err && v["error"]["code"] == "PROTECTED_RESOURCE", "{v}");
}

#[tokio::test]
async fn case_and_short_names_are_canonicalized() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("LongDirectoryName")).unwrap();
    std::fs::write(h.projects.join("LongDirectoryName").join("File.txt"), "x").unwrap();
    let r = h
        .ok(
            "fs_stat",
            json!({ "path": h.path("longdirectoryname/FILE.TXT") }),
        )
        .await;
    assert!(
        r["metadata"]["path"]
            .as_str()
            .unwrap()
            .ends_with(r"LongDirectoryName\File.txt"),
        "{r}"
    );
    // 8.3 alias (when short names are enabled on the volume).
    let out = std::process::Command::new("cmd")
        .args(["/c", "dir", "/x"])
        .current_dir(&h.projects)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    if let Some(short) = text.split_whitespace().find(|w| w.starts_with("LONGDI~")) {
        let r = h
            .ok(
                "fs_stat",
                json!({ "path": h.path(&format!("{short}/File.txt")) }),
            )
            .await;
        assert!(
            r["metadata"]["path"]
                .as_str()
                .unwrap()
                .contains("LongDirectoryName"),
            "{r}"
        );
    }
}

#[tokio::test]
async fn junction_escapes_are_classified_by_destination() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("project")).unwrap();
    let outside_dir = h.outside.join("data");
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::fs::write(outside_dir.join("in.txt"), "outside").unwrap();
    junction(&h.projects.join("project").join("link"), &outside_dir);
    // Writing through the junction is an external write.
    h.needs_approval(
        "fs_write_text",
        json!({ "path": "project/link/new.txt", "content": "x" }),
    )
    .await;
    assert!(!outside_dir.join("new.txt").exists());
    h.needs_approval("fs_delete", json!({ "path": "project/link/in.txt" }))
        .await;
    assert!(outside_dir.join("in.txt").exists());
    // Deleting the junction itself removes the link, not the target.
    h.ok("fs_delete", json!({ "path": "project/link" })).await;
    assert!(outside_dir.join("in.txt").exists());
    assert!(!h.projects.join("project").join("link").exists());

    // Junction to a protected location is protected.
    let ssh = h.outside.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_ed25519"), "PRIVATE").unwrap();
    junction(&h.projects.join("project").join("keys"), &ssh);
    let (err, v) = h
        .call("fs_read_text", json!({ "path": "project/keys/id_ed25519" }))
        .await;
    assert!(err && v["error"]["code"] == "PROTECTED_RESOURCE", "{v}");
    let (err, v) = h.call("fs_list", json!({ "path": "project/keys" })).await;
    assert!(err && v["error"]["code"] == "PROTECTED_RESOURCE", "{v}");
    // Recursive copy skips links instead of following them.
    std::fs::write(h.projects.join("project").join("a.txt"), "a").unwrap();
    let c = h
        .ok(
            "fs_copy",
            json!({ "source": "project", "destination": "copy", "recursive": true }),
        )
        .await;
    assert_eq!(c["skipped_links"].as_array().unwrap().len(), 1, "{c}");
    assert!(!h.projects.join("copy").join("keys").exists());
    // Recursive delete does not traverse into the junction target.
    h.ok("fs_delete", json!({ "path": "project", "recursive": true }))
        .await;
    assert!(ssh.join("id_ed25519").exists());
}

#[tokio::test]
async fn symlink_escapes_when_symlinks_are_available() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("p")).unwrap();
    let target = h.outside.join("target.txt");
    std::fs::write(&target, "outside").unwrap();
    let link = h.projects.join("p").join("sl.txt");
    if std::os::windows::fs::symlink_file(&target, &link).is_err() {
        eprintln!("symlink creation not permitted (Developer Mode off); skipping");
        return;
    }
    h.needs_approval(
        "fs_write_text",
        json!({ "path": "p/sl.txt", "content": "x" }),
    )
    .await;
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "outside");
    // Dangling links are refused rather than followed at create time.
    let dangling = h.projects.join("p").join("dangling.txt");
    std::os::windows::fs::symlink_file(h.outside.join("nope").join("created.txt"), &dangling)
        .unwrap();
    let (err, v) = h
        .call(
            "fs_write_text",
            json!({ "path": "p/dangling.txt", "content": "x" }),
        )
        .await;
    assert!(err || v["status"] == "approval_required", "{v}");
    assert!(!h.outside.join("nope").exists());
}

#[tokio::test]
async fn hard_link_aliases_are_checked() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("p")).unwrap();
    // Alias of a protected file.
    let ssh = h.outside.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_rsa"), "PRIVATE KEY DATA").unwrap();
    std::fs::hard_link(
        ssh.join("id_rsa"),
        h.projects.join("p").join("innocent.txt"),
    )
    .unwrap();
    let (err, v) = h
        .call("fs_read_text", json!({ "path": "p/innocent.txt" }))
        .await;
    assert!(err && v["error"]["code"] == "PROTECTED_RESOURCE", "{v}");
    assert!(!v.to_string().contains("PRIVATE"));
    // Alias of an ordinary external file: reads OK, mutations are ambiguous and denied.
    std::fs::write(h.outside.join("shared.txt"), "external").unwrap();
    std::fs::hard_link(
        h.outside.join("shared.txt"),
        h.projects.join("p").join("alias.txt"),
    )
    .unwrap();
    h.ok("fs_read_text", json!({ "path": "p/alias.txt" })).await;
    let (err, v) = h
        .call(
            "fs_write_text",
            json!({ "path": "p/alias.txt", "content": "modified" }),
        )
        .await;
    assert!(err && v["error"]["code"] == "PERMISSION_DENIED", "{v}");
    assert_eq!(
        std::fs::read_to_string(h.outside.join("shared.txt")).unwrap(),
        "external"
    );
    let (err, _) = h.call("fs_patch", json!({ "path": "p/alias.txt", "edits": [{ "old_text": "external", "new_text": "x" }] })).await;
    assert!(err);
}

/// A thread keeps swapping a trusted directory between a real directory and
/// a junction to an outside location while the broker writes into it. No
/// write may ever land outside.
#[tokio::test]
async fn concurrent_reparse_swaps_never_escape() {
    let h = Harness::new().await;
    let proj = h.projects.join("race");
    std::fs::create_dir_all(&proj).unwrap();
    let evil = h.outside.join("evil");
    std::fs::create_dir_all(&evil).unwrap();
    let flip = proj.join("flip");
    std::fs::create_dir_all(&flip).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (flip2, evil2, stop2) = (flip.clone(), evil.clone(), stop.clone());
    let swapper = std::thread::spawn(move || {
        let mut n = 0u64;
        while !stop2.load(Ordering::SeqCst) {
            if std::fs::remove_dir_all(&flip2).is_ok() {
                if n.is_multiple_of(2) {
                    let _ = std::process::Command::new("cmd")
                        .args(["/c", "mklink", "/J"])
                        .arg(&flip2)
                        .arg(&evil2)
                        .output();
                } else {
                    let _ = std::fs::create_dir(&flip2);
                }
            } else {
                let _ = std::fs::remove_dir(&flip2);
                let _ = std::fs::create_dir(&flip2);
            }
            n += 1;
        }
    });
    let mut allowed = 0;
    for i in 0..60 {
        let (err, v) = h
            .call(
                "fs_write_text",
                json!({ "path": format!("race/flip/f{i}.txt"), "content": "x" }),
            )
            .await;
        if !err && v["status"] != "approval_required" {
            allowed += 1;
        }
    }
    stop.store(true, Ordering::SeqCst);
    swapper.join().unwrap();
    let escaped: Vec<_> = std::fs::read_dir(&evil).unwrap().flatten().collect();
    assert!(
        escaped.is_empty(),
        "files escaped through a swapped junction: {escaped:?}"
    );
    eprintln!("{allowed} writes landed inside the trusted directory");
}

#[tokio::test]
async fn approvals_and_tasks_are_owner_scoped() {
    let h = Harness::new().await;
    let id = h
        .needs_approval(
            "fs_write_text",
            json!({ "path": h.outside.join("x.txt").display().to_string(), "content": "x" }),
        )
        .await;
    h.core
        .decide_approval(&id, LocalDecision::AllowOnce)
        .unwrap();
    let (_, other) = h.new_client("Other");
    for tool in ["approval_status", "approval_resume"] {
        let (err, v) = h.call_as(&other, tool, json!({ "approval_id": id })).await;
        assert!(err && v["error"]["code"] == "NOT_FOUND", "{tool}: {v}");
    }
    assert!(!h.outside.join("x.txt").exists());
    // The owner can still resume.
    h.ok("approval_resume", json!({ "approval_id": id })).await;
    assert!(h.outside.join("x.txt").exists());
}

#[tokio::test]
async fn agents_cannot_approve_or_change_settings() {
    let h = Harness::new().await;
    let tools = h
        .core
        .tools
        .all()
        .iter()
        .map(|t| t.name)
        .collect::<Vec<_>>();
    for forbidden in [
        "approval_decide",
        "approval_allow",
        "settings_update",
        "settings_set",
        "emergency_resume",
    ] {
        assert!(
            !tools.contains(&forbidden),
            "{forbidden} must not be exposed"
        );
    }
    let (err, v) = h
        .call(
            "approval_resume",
            json!({ "approval_id": "apr_01JUNKJUNKJUNKJUNKJUNKJUNK" }),
        )
        .await;
    assert!(err, "{v}");
}

#[tokio::test]
async fn shell_preflight_detects_explicit_external_writes() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("p")).unwrap();
    let out = h.outside.join("shell.txt").display().to_string();
    for cmd in [
        format!("echo x > \"{out}\""),
        format!("copy nul \"{out}\""),
        format!("del /q \"{out}\""),
    ] {
        h.needs_approval("shell_cmd", json!({ "command": cmd, "cwd": h.path("p") }))
            .await;
    }
    h.needs_approval(
        "shell_powershell",
        json!({ "script": format!("Set-Content -Path '{out}' -Value x"), "cwd": h.path("p") }),
    )
    .await;
    h.needs_approval(
        "shell_powershell",
        json!({ "script": format!("[IO.File]::WriteAllText('{out}', 'x')"), "cwd": h.path("p") }),
    )
    .await;
    assert!(!Path::new(&out).exists());
    // Unknown commands outside the workspace need approval; inside they run with a warning.
    h.needs_approval(
        "shell_cmd",
        json!({ "command": "somerandomtool.exe --go", "cwd": h.outside.display().to_string() }),
    )
    .await;
    let (err, v) = h
        .call(
            "shell_cmd",
            json!({ "command": "echo inside", "cwd": h.path("p") }),
        )
        .await;
    assert!(!err && v["status"] == "completed", "{v}");
}

#[tokio::test]
async fn processes_run_in_jobs_and_die_on_kill() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("p")).unwrap();
    // A child that spawns a grandchild; killing the task must end both.
    let v = h
        .ok("shell_cmd", json!({ "command": "start /b ping -n 120 127.0.0.1 >nul & ping -n 120 127.0.0.1 >nul", "cwd": h.path("p"), "background": true }))
        .await;
    let task = v["task_id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(800)).await;
    let t = h.ok("task_get", json!({ "task_id": task })).await;
    assert!(t["active_processes"].as_u64().unwrap() >= 2, "{t}");
    h.ok("task_kill", json!({ "task_id": task })).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let t = h.ok("task_get", json!({ "task_id": task })).await;
    assert_eq!(t["status"], "killed");
}
